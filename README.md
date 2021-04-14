```
  __                        _ _  __       
 / _|_ __ _   _  __ _  __ _| (_)/ _|_   _ 
| |_| '__| | | |/ _` |/ _` | | | |_| | | |
|  _| |  | |_| | (_| | (_| | | |  _| |_| |
|_| |_|   \__,_|\__, |\__,_|_|_|_|  \__, |
                |___/               |___/
```

## Background

Traditionally, [Puppy Linux](http://puppylinux.com/) has been based on two kinds of installation:
1. "Full installation", where the operating system is installed on a bootable partition, like most other distros.
2. "Frugal installation", where operating system consists of a squashfs image placed on a bootable partition, a writable file system image placed alongside it (the *savefile*) and an initramfs that mounts an [aufs](http://aufs.sourceforge.net/) union file system where the squashfs image is a read-only layer, and changes to the file system are saved in the savefile.

In Puppy jargon, this is translated into a variable called *PUPMODE*. PUPMODE=2 means full installation, and PUPMODE=13 means frugal installation.

This is an over-simplified explanation because PUPMODE is already [explained in detail](https://bkhome.org/archive/puppylinux/development/howpuppyworks.html) by Barry Kauler, the original creator of Puppy and the architect behind its boot process.

Generally, the full installation type is reserved to cases where frugal installation is impossible, because the frugal installation type has many advantages:
1. It takes less space: the squashfs image containing the operating system is compressed.
2. It's easier to install, update, inspect and repair: the operating system itself is just the kernel, the initramfs and a squashfs image; the savefile can be deleted to repair or reset the operating system, and backup is a matter of copying the savefile.
3. It makes it possible to install multiple operating systems (say, different variants of Puppy) on the same partition.

However, inability to perform a frugal installation is not a purely theoretical problem:
1. Some non-x86 devices have boot loaders that don't support initramfs boot.
2. Sometimes, one might wish to take the highly modified kernel from a different distro (say, from [Chrome OS](https://www.chromium.org/chromium-os)) in its binary form and use it to boot Puppy, but that kernel is built without initramfs support.
3. The Puppy initramfs is sensitive to boot device types (e.g. it must contain the required drivers), file system types (e.g. *guess_fstype* needs to be able to detect the file system on the boot partition) and so on; something along the boot process might not work in some configuration where non-initramfs boot would work just fine.
4. Sometimes, the kernel command-line of kernels borrowed from other operating systems is [hardcoded](https://github.com/archlinuxarm/PKGBUILDs/blob/master/core/linux-veyron/cmdline) in the kernel image.
5. The use of a savefile is inconvenient: it's slower than saving directly on a partition, it's hard to decide how much space to allocate for the savefile, and limiting the save file size to allow future operating system upgrades is a big compromise on computers with a small 16 GB disk.

## Overview

frugalify is a small, static executable that can be placed on a bootable partition and configured to act as PID 1 via the *init=* kernel parameter.

frugalify simulates what the Puppy initramfs does:
1. It looks for a squashfs image on the partition mounted by the kernel.
2. It creates the */save* directory on the partition.
3. It mounts a union file system.
4. It starts the Puppy init process under the union file system.

The result is an initramfs-less Puppy installation that combines the advantages of both installation methods:
1. The operating system is small, because it's compressed.
2. Updates, repair, etc' are easy, because the operating system is the kernel, the frugalify executable and a squashfs image.
3. Persistent storage is implemented using a disk partition, and the user does not have to reserve space for it, or think about available free space (i.e. empty the browser cache) all the time.
4. It's portable: if the kernel can mount the partition, a semi-frugal installation using frugalify is possible.

## Union File Systems

frugalify supports:
- [overlay](https://www.kernel.org/doc/html/latest/filesystems/overlayfs.html)
- [aufs](http://aufs.sourceforge.net/)

## Encryption

The [aufs](http://aufs.sourceforge.net/) variant of frugalify supports encryption of the */save* directory using [file system level encryption](https://www.kernel.org/doc/html/latest/filesystems/fscrypt.html).

In every boot, the user is required to specify a passphrase. frugalify computes its SHA512 using [mbedtls](https://tls.mbed.org) to generate a 64-byte encryption key.

## Releases

Pre-built, statically-linked and [portable](https://github.com/dimkr/toolchains/) binaries linked against [musl](https://musl.libc.org/) are available in the [releases page](https://github.com/dimkr/frugalify/releases).

## Credits and Legal Information

frugalify is free and unencumbered software released under the terms of the MIT license; see COPYING for the license text.

The ASCII art logo at the top was made using [FIGlet](http://www.figlet.org/).