#include <unistd.h>
#include <linux/loop.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <sys/mount.h>
#include <signal.h>
#include <pwd.h>
#include <sys/wait.h>
#include <sys/reboot.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <time.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/klog.h>
#include <syslog.h>
#include <sys/sysmacros.h>

#ifdef HAVE_FSCRYPT
#   include <linux/fscrypt.h>
#   include <mbedtls/sha512.h>
#endif

#ifndef LOOP_CTL_GET_FREE
#   define LOOP_CTL_GET_FREE 0x4C82
#endif
#ifndef LOOP_CTL_REMOVE
#   define LOOP_CTL_REMOVE 0x4C81
#endif

#ifndef FITRIM
#   define FITRIM _IOWR('X', 121, struct fstrim_range)

struct fstrim_range {
    uint64_t start;
    uint64_t len;
    uint64_t minlen;
};
#endif

#define MAXSFS 32

#ifdef HAVE_AUFS
#   define FS "aufs"
#   define FSOPTS_HEAD "br=/upper/save"
#else
#   define FS "overlay"
#   define FSOPTS_HEAD "upperdir=/upper/save,workdir=/upper/.work,lowerdir="
#endif

#define CLEAR_TTY "\033[2J\033[H"
#define HIDE_KEY "\033[32m\033[102m"
#define RESET_TTY "\033[39m\033[49m"

#define FSTRIM_FREQ (60 * 60 * 24 * 7)
#define RESPAWN_DELAY 1

enum {
    BOOTCODE_NOCOPY = 1,
    BOOTCODE_RAM    = 1 << 1,
};

static const struct sockaddr_un devlog = {.sun_family = AF_UNIX, .sun_path = "/dev/log"};

static inline void do_autoclose(void *fdp)
{
    if (*(int *)fdp != -1)
        close(*(int *)fdp);
}

#define autoclose __attribute__((cleanup(do_autoclose)))

static void fakelogin(void)
{
    struct passwd *user;

    user = getpwuid(geteuid());

    if (!user ||
        (setenv("USER", user->pw_name, 1) < 0) ||
        (setenv("HOME", user->pw_dir, 1) < 0) ||
        (setenv("SHELL", user->pw_shell, 1) < 0) ||
        (chdir(user->pw_dir) < 0))
        return;

    execlp(user->pw_shell, user->pw_shell, "-l", (char *)NULL);
}

static void do_cttyhack(void)
{
    autoclose int fd = -1;

    if (setsid() < 0)
        return;

    fd = open("/dev/console", O_RDWR);
    if ((fd < 0) ||
        (ioctl(fd, TIOCSCTTY, NULL) < 0) ||
        (dup2(fd, STDIN_FILENO) < 0) ||
        (dup2(fd, STDOUT_FILENO) < 0) ||
        (dup2(fd, STDERR_FILENO) < 0))
        return;

    close(fd);
    fd = -1;

    fakelogin();
}

static void delay(const time_t sec)
{
    struct timespec req = {.tv_sec = sec}, rem;

    while (1) {
        if (nanosleep(&req, &rem) == 0)
            break;

        if (errno != EINTR)
            break;

        memcpy(&req, &rem, sizeof(struct timespec));
    }
}

static pid_t cttyhack(const time_t sec)
{
    pid_t pid;
    sigset_t mask;

    pid = fork();
    if (pid == 0) {
        if ((sigfillset(&mask) < 0) ||
            (sigprocmask(SIG_UNBLOCK, &mask, NULL) < 0))
            exit(EXIT_FAILURE);

        if (sec > 0)
            delay(sec);

        do_cttyhack();
        exit(EXIT_FAILURE);
    }

    return pid;
}

static int initscript(void)
{
    pid_t pid;
    sigset_t mask;
    int status;

    pid = fork();
    if (pid == 0) {
        if ((sigfillset(&mask) < 0) ||
            (sigprocmask(SIG_UNBLOCK, &mask, NULL) < 0))
            exit(EXIT_FAILURE);

        execl("/etc/rc.d/rc.sysinit", "/etc/rc.d/rc.sysinit", (char *)NULL);
        exit(EXIT_FAILURE);
    }
    else if ((pid < 0) ||
             (waitpid(pid, &status, 0) != pid) ||
             !WIFEXITED(status))
        return -1;

    return 0;
}

static int init(void)
{
    sigset_t mask;
    pid_t pid, reaped;
    siginfo_t sig = {.si_signo = SIGUSR2};
    int status, ret;

    openlog("init", 0, LOG_DAEMON);

    /* block SIGCHLD, SIGTERM (poweroff) and SIGUSR2 (reboot) */
    if ((sigemptyset(&mask) < 0) ||
        (sigaddset(&mask, SIGCHLD) < 0) ||
        (sigaddset(&mask, SIGTERM) < 0) ||
        (sigaddset(&mask, SIGUSR2) < 0) ||
        (sigprocmask(SIG_SETMASK, &mask, NULL) < 0))
        goto shutdown;

    syslog(LOG_INFO, "running init script");
    if (initscript() < 0)
        goto shutdown;

    write(STDOUT_FILENO, CLEAR_TTY, sizeof(CLEAR_TTY) - 1);

    syslog(LOG_INFO, "starting login shell");
    pid = cttyhack(0);
    if (pid < 0)
        goto shutdown;

    do {
        if ((sigwaitinfo(&mask, &sig) < 0) || (sig.si_signo != SIGCHLD))
            break;

        reaped = waitpid(sig.si_pid, &status, WNOHANG);
        if (reaped < 0) {
            if (errno != ECHILD)
                break;
            continue;
        }
        else if (reaped == 0)
            continue;

        if (!WIFEXITED(status) && !WIFSIGNALED(status))
            continue;

        if (sig.si_pid == pid) {
            syslog(LOG_INFO, "restarting login shell");

            pid = cttyhack(RESPAWN_DELAY);
            if (pid < 0)
                goto shutdown;
        }
    } while (1);

shutdown:
    closelog();

    ret = kill(-1, SIGTERM);
    delay(2);
    if (ret == 0)
        kill(-1, SIGKILL);

    sync();

    if (vfork() == 0) {
        if (sig.si_signo == SIGUSR2)
            reboot(RB_POWER_OFF);
        else
            reboot(RB_AUTOBOOT);
    }

    return EXIT_FAILURE;
}

// use of sprintf() can double the executable size
static char *itoa(char *s, int i)
{
    if (i >= 10)
        s = itoa(s, i / 10);

    *s = '0' + i % 10;
    ++s;
    *s = '\0';
    return s;
}

static int get_free_lo(void)
{
    autoclose int ctl = -1;

    ctl = open("/upper/save/dev/loop-control", O_RDONLY);
    if (ctl < 0)
        return -1;

    return ioctl(ctl, LOOP_CTL_GET_FREE);
}

static void remove_lo(int id)
{
    autoclose int ctl = -1;

    ctl = open("/dev/loop-control", O_RDONLY);
    if (ctl > 0)
        ioctl(ctl, LOOP_CTL_REMOVE, id);
}

static char *get_lo_path(int i)
{
    static char loop[sizeof("/upper/save/dev/loop99")] = "/upper/save/dev/loop";

    itoa(loop + sizeof("/upper/save/dev/loop") - 1, i);
    return loop;
}

static const char *losetup(const char *sfs, const int i)
{
    struct stat stbuf;
    struct loop_info64 info = {.lo_flags = LO_FLAGS_READ_ONLY};
    const char *loop;
    autoclose int loopfd = -1, sfsfd = -1;

    sfsfd = open(sfs, O_RDONLY);
    if (sfsfd < 0)
        return NULL;

    if (fstat(sfsfd, &stbuf) < 0)
        return NULL;

    loop = get_lo_path(i);

    loopfd = open(loop, O_RDONLY);
    if (loopfd < 0)
        return NULL;

    if (ioctl(loopfd, LOOP_SET_FD, sfsfd) < 0)
        return NULL;

#ifdef HAVE_STRLCPY
    strlcpy(info.lo_file_name, sfs, sizeof(info.lo_file_name));
#else
    strncpy((char *)info.lo_file_name, sfs, sizeof(info.lo_file_name));
    info.lo_file_name[sizeof(info.lo_file_name) - 1] = '\0';
#endif
    info.lo_sizelimit = (uint64_t)stbuf.st_size;
    info.lo_flags = LO_FLAGS_READ_ONLY;
    if (ioctl(loopfd, LOOP_SET_STATUS64, &info) < 0)
        return NULL;

    return loop;
}

static void losetup_d(const int i)
{
    int loopfd;
    autoclose int ctl = -1;

    loopfd = open(get_lo_path(i), O_RDWR);
    if (loopfd < 0)
        return;

    ioctl(loopfd, LOOP_CLR_FD);
    close(loopfd);

    ctl = open("/upper/save/dev/loop-control", O_RDONLY);
    if (ctl >= 0)
        ioctl(ctl, LOOP_CTL_REMOVE, i);
}

static int sfscmp(const void *a, const void *b)
{
    const char *as = *(const char **)a, *bs = *(const char **)b, *abase, *bbase;
    int m, n;

    abase = strrchr(as, '/');
    if (abase)
        abase = &abase[1];
    else
        abase = as;

    bbase = strrchr(bs, '/');
    if (bbase)
        bbase = &bbase[1];
    else
        bbase = bs;

    m = strncmp(abase, "puppy_", sizeof("puppy_") - 1);
    n = strncmp(bbase, "puppy_", sizeof("puppy_") - 1);

    if ((m == 0) && (n != 0))
        return 1;

    if ((m != 0) && (n == 0))
        return -1;

    return -strverscmp(abase, bbase);
}

#ifdef HAVE_FSCRYPT

static unsigned int read_key(unsigned char key[FSCRYPT_MAX_KEY_SIZE])
{
    unsigned char buf[32];
    unsigned int len;

    for (len = 0; len < sizeof(buf); ++len) {
        if (read(STDIN_FILENO, &buf[len], sizeof(buf[len]) ) != sizeof(buf[len]))
            return 0;

        if (buf[len] == '\n')
            break;
    }

    mbedtls_sha512_ret(buf, len, key, 0);
    return len;
}

static void fscrypt(const char *path)
{
    static unsigned char buf[sizeof(struct fscrypt_add_key_arg) + FSCRYPT_MAX_KEY_SIZE];
    struct fscrypt_add_key_arg *arg = (struct fscrypt_add_key_arg *)buf;
    struct fscrypt_remove_key_arg remove = {
        .key_spec = {
            .type = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER,
        },
    };
    struct fscrypt_policy_v2 policy = {
        .version = FSCRYPT_POLICY_V2,
        .contents_encryption_mode = FSCRYPT_MODE_AES_256_XTS,
        .filenames_encryption_mode = FSCRYPT_MODE_AES_256_CTS,
        .flags = FSCRYPT_POLICY_FLAGS_PAD_32,
    };
    unsigned int len;
    int fd;

    if (write(STDOUT_FILENO, "Key: ", sizeof("Key: ") - 1) != sizeof("Key: ") - 1)
        return;

    write(STDOUT_FILENO, HIDE_KEY, sizeof(HIDE_KEY) - 1);
    len = read_key(&buf[sizeof(*arg)]);
    write(STDOUT_FILENO, RESET_TTY, sizeof(RESET_TTY) - 1);
    if (len == 0)
        return;

    fd = open(path, O_RDONLY);
    if (fd < 0)
        return;

    *arg = (struct fscrypt_add_key_arg){
        .key_spec = {
            .type = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER,
        },
        .raw_size = sizeof(buf) - sizeof(*arg),
    };

    if (ioctl(fd, FS_IOC_ADD_ENCRYPTION_KEY, buf) < 0) {
        close(fd);
        return;
    }

    memcpy(policy.master_key_identifier,
           arg->key_spec.u.identifier,
           sizeof(policy.master_key_identifier));

    if (ioctl(fd, FS_IOC_SET_ENCRYPTION_POLICY, &policy) < 0) {
        memcpy(remove.key_spec.u.identifier,
               arg->key_spec.u.identifier,
               sizeof(remove.key_spec.u.identifier));
        ioctl(fd, FS_IOC_REMOVE_ENCRYPTION_KEY, &remove);
    }

    close(fd);
}

#endif

static int oom_score_adj(void)
{
    autoclose int adj = -1;

    adj = open("/proc/self/oom_score_adj", O_WRONLY);
    if (adj < 0)
        return -1;

    if (write(adj, "1000", sizeof("1000") - 1) != sizeof("1000") - 1)
        return -1;

    return 0;
}

static int get_ver(char *buf, size_t len)
{
    static char *const argv[] = {
        "/bin/sh",
        "-c",
        ". /etc/DISTRO_SPECS && echo -n \"$DISTRO_VERSION\"",
        NULL
    };
    int pipefd[2];
    ssize_t out;
    autoclose int infd = -1, outfd = -1;
    pid_t pid;
    int status;

    if (pipe(pipefd) < 0)
        return -1;

    infd = pipefd[0];
    outfd = pipefd[1];

    pid = fork();
    switch (pid) {
    case 0:
        if (dup2(outfd, STDOUT_FILENO) == STDOUT_FILENO)
            execv(argv[0], argv);

        exit(EXIT_FAILURE);

    case -1:
        return -1;
    }

    if (waitpid(pid, &status, 0) != pid)
        return -1;

    out = read(infd, buf, len - 1);
    if ((out <= 0) || (out == (len - 1)))
        return -1;

    if ((buf[0] < '0') || (buf[0] > '9'))
        return -1;

    buf[out] = '\0';
    return 0;
}

static void do_pfixram(char **sfs, const int nsfs)
{
    static char ver[sizeof("999.999.999")];
    struct stat stbuf;
    sigset_t mask;
    const char *base;
    void *p;
    long minsize;
    int fd, sig, i, locked = 0;

    if (prctl(PR_SET_NAME, "pfixram") < 0)
        return;

    if ((sigemptyset(&mask) < 0) ||
        (sigaddset(&mask, SIGTERM) < 0) ||
        (sigprocmask(SIG_SETMASK, &mask, NULL) < 0))
        return;

    minsize = sysconf(_SC_PAGESIZE);
    if (minsize <= 0)
        return;

    if (get_ver(ver, sizeof(ver)) < 0)
        ver[0] = '\0';

    for (i = nsfs -1; i >= 0; --i) {
        base = strrchr(sfs[i], '/');
        if (base)
            ++base;
        else
            base = sfs[i];

        if ((strncmp(base, "zdrv_", sizeof("zdrv_") - 1) == 0) ||
            (strncmp(base, "fdrv_", sizeof("fdrv_") - 1) == 0) ||
            (strncmp(base, "devx_", sizeof("devx_") - 1) == 0) ||
            (strncmp(base, "docx_", sizeof("docx_") - 1) == 0) ||
            (strncmp(base, "nlsx_", sizeof("nlsx_") - 1) == 0))
            continue;

        if (ver[0] && !strstr(base, ver))
            continue;

        fd = open(sfs[i], O_RDONLY);
        if (fd < 0)
            continue;

        if ((fstat(fd, &stbuf) < 0) || (stbuf.st_size < minsize)) {
            close(fd);
            continue;
        }

        p = mmap(NULL,
                 (size_t)stbuf.st_size,
                 PROT_READ,
                 MAP_PRIVATE | MAP_POPULATE,
                 fd,
                 0);
        if (p == MAP_FAILED) {
            if (errno == ENOMEM)
                return;

            close(fd);
            continue;
        }

        if (mlock2(p, (size_t)stbuf.st_size, MLOCK_ONFAULT) < 0) {
            if (errno == ENOMEM)
                return;

            munmap(p, (size_t)stbuf.st_size);
            close(fd);
            continue;
        }

        syslog(LOG_INFO, "locked %s to RAM", sfs[i]);
        ++locked;
    }

    if (locked > 0) {
        while (1) {
            if ((sigwait(&mask, &sig) < 0) || (sig == SIGTERM))
                break;
        }
    }
}

static void pfixram(char **sfs, const int nsfs)
{
    if (fork() == 0) {
        if (chdir("/initrd") < 0)
            exit(EXIT_FAILURE);

        // lower our priority so we don't starve I/O intensive applications
        if (setpriority(PRIO_PROCESS, 0, 10) < 0)
            exit(EXIT_FAILURE);

        // pfixram should be the first process to kill when out of memory
        if (oom_score_adj() < 0)
            exit(EXIT_FAILURE);

        openlog("pfixram", 0, LOG_DAEMON);

        do_pfixram(sfs, nsfs);

        closelog();
        exit(EXIT_FAILURE);
    }
}

static int memexec(const int self, char *argv[])
{
    struct stat stbuf;
    char buf[16];
    off_t total = 0;
    ssize_t out;
    const char *comm;
    void *p;
    autoclose int memfd = -1;

    comm = getenv("COMM");
    if (comm) {
        close(self);

        if (unsetenv("COMM") < 0)
            return -1;

        return prctl(PR_SET_NAME, comm);
    }

    if (prctl(PR_GET_NAME, buf) < 0)
        return -1;

    if (setenv("COMM", buf, 1) < 0)
        return -1;

    memfd = memfd_create(argv[0], 0);
    if (memfd < 0)
        return -1;

    if (fcntl(memfd, F_SETFD, FD_CLOEXEC) < 0)
        return -1;

    if ((fstat(self, &stbuf) < 0) || (stbuf.st_size == 0))
        return -1;

    p = mmap(NULL,
             (size_t)stbuf.st_size,
             PROT_READ,
             MAP_PRIVATE,
             self,
             0);
    if (p == MAP_FAILED)
        return -1;

    do {
        out = write(memfd, (unsigned char *)p + total, stbuf.st_size - total);
        if (out <= 0)
            return -1;

        total += (off_t)out;
    } while (total < stbuf.st_size);

    munmap(p, (size_t)stbuf.st_size);
    close(self);

    return fexecve(memfd, argv, environ);
}

static int getcodes(unsigned int *bootcodes)
{
    static char buf[256];
    ssize_t len;
    char *tok, *save;
    autoclose int cmdline = -1;

    cmdline = open("/upper/cmdline", O_RDONLY);
    if (cmdline < 0)
        return -1;

    len = read(cmdline, buf, sizeof(buf));
    if (len < 0)
        return -1;
    else if (len == 0)
        return 0;

    buf[len - 1] = '\0';

    tok = strtok_r(buf, " ", &save);
    do {
        if (strcmp(tok, "pfix=nocopy") == 0)
            *bootcodes |= BOOTCODE_NOCOPY;
        else if (strcmp(tok, "pfix=ram") == 0)
            *bootcodes |= BOOTCODE_RAM;

        tok = strtok_r(NULL, " ", &save);
    } while (tok);

    return 0;
}

static char *getroot(void)
{
    static char dst[512];
    static char path[sizeof("/upper/dev/block/4294967295:4294967295")] = "/upper/dev/block/";
    struct stat stbuf;
    ssize_t out;
    char *p, *dev;

    if (stat("/", &stbuf) < 0)
        return NULL;

    p = itoa(path + sizeof("/upper/dev/block/") - 1, major(stbuf.st_dev));
    *p = ':';
    itoa(p + 1, minor(stbuf.st_dev));

    out = readlink(path, dst, sizeof(dst));
    if ((out <= 0) || (out >= sizeof(dst)))
        return NULL;

    dst[out] = '\0';
    p = basename(dst);

    dev = p - (sizeof("/dev/") - 1);
    if (dev < dst)
        return NULL;

    memcpy(dev, "/dev/", sizeof("/dev/") - 1);
    return dev;
}

static int binmount(const char *dev, const char *target, const char *opts)
{
    pid_t pid, reaped;
    int status;

    pid = fork();
    if (pid == 0) {
        execl("/bin/mount", "/bin/mount", "-o", opts, dev, target, (char *)NULL);
        exit(EXIT_FAILURE);
    }
    else if (pid < 0)
        return -1;

    reaped = waitpid(pid, &status, 0);
    if (((reaped < 0) && (errno != ECHILD)) ||
        (!WIFEXITED(status) || (WEXITSTATUS(status) != EXIT_SUCCESS)))
        return -1;

    return 0;
}

static void fstrim(const int fd)
{
    struct timespec now, prev;
    struct stat stbuf;
    struct fstrim_range range = {.len = ULLONG_MAX};

    if (clock_gettime(CLOCK_REALTIME, &now) < 0)
        return;

    if (now.tv_sec < FSTRIM_FREQ)
        return;

    prev.tv_sec = now.tv_sec - FSTRIM_FREQ;
    prev.tv_nsec = now.tv_nsec;

    if (fstat(fd, &stbuf) < 0)
        return;

    if ((stbuf.st_mtim.tv_sec > prev.tv_sec) ||
        ((stbuf.st_mtim.tv_sec == prev.tv_sec) &&
         (stbuf.st_mtim.tv_nsec >= prev.tv_nsec)))
        return;

    if (ioctl(fd, FITRIM, &range) == 0)
        syslog(LOG_INFO, "successfully discarded unused blocks");
    else
        syslog(LOG_WARNING, "failed to discard unused blocks: %d", errno);

    futimens(fd, NULL);
}

static void do_fstrimd(const int fd)
{
    siginfo_t sig;
    struct timespec ts = {.tv_sec = FSTRIM_FREQ + 120};
    sigset_t mask;

    fstrim(fd);

    if (prctl(PR_SET_NAME, "fstrimd") < 0)
        return;

    if ((sigemptyset(&mask) < 0) ||
        (sigaddset(&mask, SIGTERM) < 0) ||
        (sigprocmask(SIG_SETMASK, &mask, NULL) < 0))
        return;

    while (1) {
        if (sigtimedwait(&mask, &sig, &ts) < 0) {
            if (errno == EAGAIN)
                fstrim(fd);
            else if (errno != EINTR)
                break;
        } else if (sig.si_signo == SIGTERM)
            break;
    }
}

static void fstrimd(void)
{
    autoclose int fd = -1;

    fd = open("/initrd/upper", O_DIRECTORY);
    if (fd < 0)
        return;

    if (fork() == 0) {
        openlog("fstrimd", 0, LOG_DAEMON);

        do_fstrimd(fd);

        closelog();
        exit(EXIT_FAILURE);
    }
}

static void do_syslogd(const int sockfd, const int logfd)
{
    static char buf[1024];
    sigset_t mask;
    ssize_t len, out, total;

    if (prctl(PR_SET_NAME, "syslogd") < 0)
        return;

    if ((sigfillset(&mask) < 0) ||
        (sigprocmask(SIG_UNBLOCK, &mask, NULL) < 0))
        return;

    while (1) {
        len = recv(sockfd, buf, sizeof(buf) - 2, 0);
        if (len <= 0)
            break;

        if (buf[len - 1] != '\n') {
            buf[len] = '\n';
            ++len;
            buf[len] = '\0';
        }

        for (total = 0; total < len; total += out) {
            out = write(logfd, buf + total, (size_t)len - total);
            if (out <= 0)
                return;
        }
    }
}

static int syslogd(void)
{
    autoclose int sockfd = -1, logfd = -1;
    pid_t pid;

    sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sockfd < 0)
        return -1;

    unlink(devlog.sun_path);
    if (bind(sockfd, (struct sockaddr *)&devlog, sizeof(devlog)) < 0)
        return -1;

    if ((mkdir("/var/log", 0755) < 0) && (errno != EEXIST))
        return -1;

    logfd = open("/var/log/messages", O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (logfd < 0)
        return -1;

    pid = fork();
    if (pid == 0) {
        do_syslogd(sockfd, logfd);
        exit(EXIT_FAILURE);
    }
    else if (pid < 0)
        return -1;

    return 0;
}

static void do_klogd(const int kmsg)
{
    static char buf[1024];
    sigset_t mask;
    ssize_t len;
    int sockfd;

    if (prctl(PR_SET_NAME, "klogd") < 0)
        return;

    if ((sigfillset(&mask) < 0) ||
        (sigprocmask(SIG_UNBLOCK, &mask, NULL) < 0))
        return;

    sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sockfd < 0)
        return;

    if (connect(sockfd, (const struct sockaddr *)&devlog, sizeof(devlog)) < 0)
        return;

    if (klogctl(6, NULL, 0) < 0)
        return;

    while (1) {
        len = read(kmsg, buf, sizeof(buf));
        if (len <= 0)
            break;

        send(sockfd, buf, (size_t)len, 0);
    }
}

static void klogd(void)
{
    autoclose int kmsg = -1;

    kmsg = open("/proc/kmsg", O_RDONLY);
    if (kmsg < 0)
        return;

    if (fork() == 0) {
        do_klogd(kmsg);
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char *argv[])
{
    static const char *dirs[] = {
        "/upper/save",
#ifndef HAVE_AUFS
        "/upper/.work",
#endif
        "/upper/.pup_new",
        "/upper/save/proc",
        "/upper/save/dev",
        "/upper/save/initrd",
        "/upper/save/mnt",
        "/upper/save/mnt/home",
    };
    static char sfspath[MAXSFS][128], br[1024] = FSOPTS_HEAD;
    struct dirent ent[MAXSFS];
    struct statvfs vfs;
    sigset_t set;
    char *sfs[MAXSFS] = {NULL}, sfsmnt[sizeof("/upper/.sfs99")] = "/upper/.sfs";
    const char *loop, *devroot;
    size_t len, brlen = sizeof(FSOPTS_HEAD) - 1;
    ssize_t out;
    DIR *root;
    struct dirent *pent;
    int nsfs = 0, i, ro = 0, self, loopid;
    unsigned int bootcodes = 0;

    // protect against accidental click
    if (getpid() != 1)
        return EXIT_FAILURE;

    if ((sigemptyset(&set) < 0) ||
        (sigaddset(&set, SIGCHLD) < 0) ||
        (sigprocmask(SIG_SETMASK, &set, NULL) < 0))
        return EXIT_FAILURE;

    // clear firmware and bootloader output on the screen
    write(STDOUT_FILENO, CLEAR_TTY, sizeof(CLEAR_TTY) - 1);

    if (statvfs("/", &vfs) < 0)
        return EXIT_FAILURE;

    if (vfs.f_flag & ST_RDONLY)
        ro = 1;
    else
        mount(NULL, "/", NULL, MS_REMOUNT | MS_NOATIME, NULL);

    root = opendir("/");
    if (!root)
        return EXIT_FAILURE;
    
    // create a list of all SFS files under /
    while ((readdir_r(root, &ent[nsfs], &pent) == 0) && (pent != NULL)) {
        len = strlen(pent->d_name);
        if ((len <= sizeof(".sfs") - 1) || 
            (memcmp(&pent->d_name[len - 4], ".sfs", sizeof(".sfs") - 1) != 0))
            continue;

        sfs[nsfs] = pent->d_name;
        switch (pent->d_type) {
        case DT_REG:
            break;

        case DT_LNK:
            out = readlink(pent->d_name,
                           sfspath[nsfs],
                           sizeof(sfspath[nsfs]) - 1);
            if (out <= 0)
                continue;
            sfspath[nsfs][out] = '\0';
            sfs[nsfs] = sfspath[nsfs];
            break;

        default:
            continue;
        }

        ++nsfs;
        if (nsfs == MAXSFS)
            break;
    }
    closedir(root);

    if (!sfs[0])
        return EXIT_FAILURE;

    if (!ro && ((mkdir("/upper", 0755) < 0) && (errno != EEXIST)))
        return EXIT_FAILURE;

    // temporarily mount proc at /upper, only to parse cmdline and access /proc/self/exe
    if (mount("proc", "/upper", "proc", 0, NULL) < 0)
        return EXIT_FAILURE;

    self = open("/upper/self/exe", O_RDONLY);
    if (self < 0)
        return EXIT_FAILURE;

    if (getcodes(&bootcodes) < 0)
        return EXIT_FAILURE;

    umount2("/upper", MNT_DETACH);

    // temporarily mount sys at /upper, only to detect /dev/root
    if (mount("sys", "/upper", "sysfs", 0, NULL) < 0)
        return EXIT_FAILURE;

    // detect the root partition, so we can mount it directly and not as /dev/root
    devroot = getroot();
    if (!devroot)
        return EXIT_FAILURE;

    umount2("/upper", MNT_DETACH);

    if ((ro || (bootcodes & BOOTCODE_RAM)) && (mount("save", "/upper", "tmpfs", 0, "size=75%") < 0))
        return EXIT_FAILURE;
    // TODO: figure out a way to make encryption work with overlayfs
#ifdef HAVE_FSCRYPT
    else if (!ro && !(bootcodes & BOOTCODE_RAM))
        fscrypt("/upper");
#endif

    for (i = 0; i < sizeof(dirs) / sizeof(dirs[0]); ++i) {
        if ((mkdir(dirs[i], 0755) < 0) && (errno != EEXIST))
            return EXIT_FAILURE;
    }

    // re-run the executable from RAM, so it can be updated on disk while
    // running
    if (memexec(self, argv) < 0)
        return EXIT_FAILURE;

    // make sure adrv, zdrv, etc' come after the main SFS
    qsort(sfs, (size_t)nsfs, sizeof(sfs[0]), sfscmp);

    // mount a devtmpfs so we have the loop%d device nodes
    if (mount("dev", "/upper/save/dev", "devtmpfs", 0, NULL) < 0)
        return EXIT_FAILURE;

    for (i = nsfs -1; i >= 0; --i) {
        itoa(sfsmnt + sizeof("/upper/.sfs") - 1, i);

        if ((mkdir(sfsmnt, 0755) < 0) && (errno != EEXIST))
            continue;

        // find a free loop device or allocate a new one
        loopid = get_free_lo();
        if (loopid < 0)
            continue;

        // bind the SFS to a loop device
        loop = losetup(sfs[i], loopid);
        if (!loop) {
            remove_lo(loopid);
            continue;
        }

        // mount the loop device
        if (mount(loop, sfsmnt, "squashfs", MS_RDONLY, "") < 0) {
            losetup_d(loopid);
            remove_lo(loopid);
            continue;
        }
    }

    for (i = 0; (i < nsfs) && (brlen < sizeof(br)); ++i) {
        itoa(sfsmnt + sizeof("/upper/.sfs") - 1, i);

#ifndef HAVE_AUFS
        if (i == 0)
            goto cpy;
#endif

        br[brlen] = ':';
        ++brlen;

#ifndef HAVE_AUFS
cpy:
#endif
        if (i < 10) {
            memcpy(&br[brlen], sfsmnt, sizeof("/upper/.sfs9") - 1);
            brlen += sizeof("/upper/.sfs9") - 1;
        }
        else {
            memcpy(&br[brlen], sfsmnt, sizeof("/upper/.sfs99") - 1);
            brlen += sizeof("/upper/.sfs99") - 1;
        }
    }
    br[brlen] = '\0';
    
    // we no longer need /dev
    umount2("/upper/save/dev", MNT_DETACH);
    rmdir("/upper/save/dev");

    // mount a union file system with the SFS mount points and /upper/save on top
    if (mount(FS, "/upper/.pup_new", FS, MS_NOATIME, br) < 0)
        return EXIT_FAILURE;
    
    if (chdir("/upper/.pup_new") < 0)
        return EXIT_FAILURE;

    // make the union file system the the file system root, or the file system
    // root for the real init and its children
#ifndef HAVE_AUFS
    if (mount(".", "/", FS, MS_MOVE, NULL) < 0)
        return EXIT_FAILURE;
#endif

    if (chroot(".") < 0)
        return EXIT_FAILURE;

    if (chdir("/") < 0)
        return EXIT_FAILURE;

    // we need access to the root partition device node
    if (mount("dev", "/dev", "devtmpfs", 0, NULL) < 0)
        return EXIT_FAILURE;

    // mount reads /proc/filesystems
    if (mount("proc", "/proc", "proc", 0, NULL) < 0)
        return EXIT_FAILURE;

    // give access to the boot partition via /mnt/home, for compatibility
    // with Puppy tools that assume its presence
    if ((!ro && (binmount(devroot, "/mnt/home", "noatime") < 0)) ||
        (ro && (binmount(devroot, "/mnt/home", "ro") < 0)))
        return EXIT_FAILURE;

    // also give processes running with the union file system as / a directory
    // outside of the union file system that can be used to add aufs branches
    if (mount("/mnt/home", "/initrd", NULL, MS_BIND, NULL) < 0)
        return EXIT_FAILURE;

    if (syslogd() == 0)
        klogd();

    if (!ro && !(bootcodes & BOOTCODE_RAM))
        fstrimd();

    if (!(bootcodes & BOOTCODE_NOCOPY))
        pfixram(sfs, nsfs);

    // run the real init under the new root file system
    return init();
}