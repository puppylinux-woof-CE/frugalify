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

#ifdef HAVE_FSCRYPT
#   include <linux/fscrypt.h>
#   include <mbedtls/sha512.h>
#endif

#ifndef LOOP_CTL_GET_FREE
#   define LOOP_CTL_GET_FREE 0x4C82
#endif

#define MAXSFS 8

#ifdef HAVE_AUFS
#   define FS "aufs"
#   define FSOPTS_HEAD "br=/save"
#else
#   define FS "overlay"
#   define FSOPTS_HEAD "upperdir=/save,workdir=/.work,lowerdir="
#endif

#define CLEAR_TTY "\033[2J\033[H"
#define HIDE_KEY "\033[32m\033[102m"
#define RESET_TTY "\033[39m\033[49m"

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

static pid_t cttyhack(void)
{
    pid_t pid;
    sigset_t mask;

    pid = fork();
    if (pid == 0) {
        if ((sigfillset(&mask) < 0) ||
            (sigprocmask(SIG_UNBLOCK, &mask, NULL) < 0))
            exit(EXIT_FAILURE);

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

    /* block SIGCHLD, SIGTERM (poweroff) and SIGUSR2 (reboot) */
    if ((sigemptyset(&mask) < 0) ||
        (sigaddset(&mask, SIGCHLD) < 0) ||
        (sigaddset(&mask, SIGTERM) < 0) ||
        (sigaddset(&mask, SIGUSR2) < 0) ||
        (sigprocmask(SIG_SETMASK, &mask, NULL) < 0))
        goto shutdown;

    if (initscript() < 0)
        goto shutdown;

    write(STDOUT_FILENO, CLEAR_TTY, sizeof(CLEAR_TTY) - 1);

    /* run a login shell */
    pid = cttyhack();
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
            pid = cttyhack();
            if (pid < 0)
                goto shutdown;
        }
    } while (1);

shutdown:
    ret = kill(-1, SIGTERM);
    sleep(2);
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

static char *get_lo_path(const int i)
{
    static char loop[sizeof("/save/dev/loop0")] = "/save/dev/loop";

    itoa(loop + sizeof("/save/dev/loop") - 1, i);
    return loop;
}

static const char *losetup(const char *sfs, const int i)
{
    struct stat stbuf;
    struct loop_info64 info = {.lo_flags = LO_FLAGS_READ_ONLY};
    const char *loop;
    autoclose int loopfd = -1, sfsfd = -1;
    
    sfsfd = open(sfs, O_RDWR);
    if (sfsfd < 0)
        return NULL;

    if (fstat(sfsfd, &stbuf) < 0)
        return NULL;

    loop = get_lo_path(i);

    loopfd = open(loop, O_RDWR);
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
    if (ioctl(loopfd, LOOP_SET_STATUS64, &info) < 0)
        return NULL;

    return loop;
}

static void losetup_d(const int i)
{
    autoclose int loopfd = -1;
    
    loopfd = open(get_lo_path(i), O_RDWR);
    if (loopfd >= 0)
        ioctl(loopfd, LOOP_CLR_FD, 0);
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

    return 0;
}

#ifdef HAVE_FSCRYPT

static unsigned int read_key(unsigned char key[FSCRYPT_MAX_KEY_SIZE])
{
    unsigned char buf[32];
    unsigned int len;
    ssize_t out;

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

static void do_pfixram(char **sfs, const int nsfs)
{
    struct stat stbuf;
    sigset_t mask;
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

    for (i = nsfs -1; i >= 0; --i) {
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
		do_pfixram(sfs, nsfs);
		exit(EXIT_FAILURE);
	}
}

static int memexec(char *argv[])
{
    struct stat stbuf;
    off_t total = 0;
    ssize_t out;
    void *p;
    autoclose int memfd = -1, self = -1;

    if (getenv("MEMEXEC"))
        return unsetenv("MEMEXEC");

    if (setenv("MEMEXEC", "1", 1) < 0)
        return -1;

    memfd = memfd_create(argv[0], 0);
    if (memfd < 0)
        return -1;

    if (fcntl(memfd, F_SETFD, FD_CLOEXEC) < 0)
        return -1;

    self = open("/init", O_RDONLY);
    if (self < 0)
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
    self = -1;

    return fexecve(memfd, argv, environ);
}

int main(int argc, char *argv[])
{
    static const char *dirs[] = {
#ifndef HAVE_AUFS
        "/.work",
#endif
        "/save/.pup_new",
        "/save/dev",
        "/save/initrd",
        "/save/mnt",
        "/save/mnt/home",
    };
    static char sfspath[MAXSFS][128], br[1024] = FSOPTS_HEAD;
    struct dirent ent[MAXSFS];
    char *sfs[MAXSFS] = {NULL}, sfsmnt[sizeof("/save/.sfs0")] = "/save/.sfs";
    const char *loop;
    size_t len, brlen = sizeof(FSOPTS_HEAD) - 1;
    ssize_t out;
    DIR *root;
    struct dirent *pent;
    int nsfs = 0, i, ro = 0;

    // protect against accidental click
    if (getpid() != 1)
        return EXIT_FAILURE;

    // re-run the executable from RAM, so it can be updated on disk while
    // running
    if (memexec(argv) < 0)
        return EXIT_FAILURE;

    // clear firmware and bootloader output on the screen
    write(STDOUT_FILENO, CLEAR_TTY, sizeof(CLEAR_TTY) - 1);

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

    if (mkdir("/save", 0755) < 0) {
        switch (errno) {
        case EEXIST:
            break;

        case EROFS:
            // we need some writable file system as the upper layer, so we mount
            // a tmpfs; we assume that /save and /.work already exist if we're
            // booting from optical media or from a corrupt file system mounted
            // read-only, and we assume that only the first mkdir() can return
            // EROFS
            if (mount("save", "/save", "tmpfs", 0, NULL) < 0)
                return EXIT_FAILURE;

            ro = 1;

            break;

        default:
            return EXIT_FAILURE;
        }
    }

    // TODO: figure out a way to make encryption work with overlayfs
#ifdef HAVE_FSCRYPT
    if (!ro)
        fscrypt("/save");
#endif

    for (i = 0; i < sizeof(dirs) / sizeof(dirs[0]); ++i) {
        if ((mkdir(dirs[i], 0755) < 0) && (errno != EEXIST))
            return EXIT_FAILURE;
    }

    // mount a devtmpfs so we have the loop%d device nodes
    if (mount("dev", "/save/dev", "devtmpfs", 0, NULL) < 0)
        return EXIT_FAILURE;
    
    // make sure adrv, zdrv, etc' come after the main SFS
    qsort(sfs, (size_t)nsfs, sizeof(sfs[0]), sfscmp);

    pfixram(sfs, nsfs);

    for (i = nsfs -1; i >= 0; --i) {
        itoa(sfsmnt + sizeof("/save/.sfs") - 1, i);

        if ((mkdir(sfsmnt, 0755) < 0) && (errno != EEXIST))
            continue;

        // bind the SFS to a loop device
        loop = losetup(sfs[i], i);
        if (!loop) {
            rmdir(sfsmnt);
            continue;
        }

        // mount the loop device
        if (mount(loop, sfsmnt, "squashfs", 0, NULL) < 0) {
            losetup_d(i);
            rmdir(sfsmnt);
            continue;
        }
    }

    for (i = 0; (i < nsfs) && (brlen < sizeof(br)); ++i) {
        itoa(sfsmnt + sizeof("/save/.sfs") - 1, i);

#ifndef HAVE_AUFS
        if (i == 0)
            goto cpy;
#endif

        br[brlen] = ':';
        ++brlen;

cpy:
        memcpy(&br[brlen], sfsmnt, sizeof("/save/.sfs0") - 1);
        brlen += sizeof("/save/.sfs0") - 1;
    }
    br[brlen] = '\0';
    
    // we no longer need /dev
    umount2("/save/dev", MNT_DETACH);
    rmdir("/save/dev");

#ifndef HAVE_AUFS
    if (ro && mount("work", "/.work", "tmpfs", 0, NULL) < 0)
        return EXIT_FAILURE;
#endif

    // mount a union file system with the SFS mount points and /save on top
    if (mount(FS, "/save/.pup_new", FS, MS_NOATIME, br) < 0)
        return EXIT_FAILURE;
    
    // give processes running with the union file system as / a directory
    // outside of the union file system that can be used to add aufs branches
    if (mount("/", "/save/.pup_new/initrd", NULL, MS_BIND, NULL) < 0)
        return EXIT_FAILURE;

    // also give access to the boot partition via /mnt/home, for compatibility
    // with Puppy tools that assume its presence
    if (mount("/", "/save/.pup_new/mnt/home", NULL, MS_BIND, NULL) < 0)
        return EXIT_FAILURE;

    if (chdir("/save/.pup_new") < 0)
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

    // run the real init under the new root file system
    return init();
}