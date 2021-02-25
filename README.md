# sed-opal-unlocker

Micro-utility for unlocking TCG-OPAL encrypted disks, utilizing CONFIG_BLK_SED_OPAL interface introduced in kernel 4.11 (but see [1] below). Also allows saving password in the running kernel for S3 Sleep support, cause it was a cheap feature to have. Based on Kyle Manna's [opalctl](https://github.com/kylemanna/opalctl) nano-utility.

[1] Since 1.0.0, sed-opal-unlocker requires kernel 5.3 or newer, cause it utilizes IOC_OPAL_MBR_DONE interface. If you need to use older kernel, checkout v0.3.1 and read "MBRunshadow vs MBRunshadowOLD" section carefully in its README if you plan to use MBRunshadow.


### Background

I'm using this tool to unlock:

- non-boot disk from custom initramfs, loaded from EFI partition sitting on another non-opal-encrypted drive. The machine is headless, cannot boot from NVME and the password is provided on an USB key, so the standard [sedutil](https://github.com/Drive-Trust-Alliance/sedutil) Pre-Boot Authentication image is not an option
- boot disk from custom PBA image (Linux EFI stub kernel + embedded initramfs) in my laptop... just cause I could.

### Features

- unlocking / locking TCG-OPAL compatible Self-Encrypting Drives
- turning off MBR shadowing after unlocking
- saving drive password into the Linux kernel (unlock support when the system is waking from S3 sleep)
- reads password from a separate file
- supports password hashing used by sedutil-cli (both original Drive Trust Alliance SHA1 version and ChubbyAnt SHA512 fork) via separate one-time-use script
- supports SATA and NVME disks
- password file can be encrypted with another passphrase (requires [libargon2](https://github.com/P-H-C/phc-winner-argon2))


### What this utility cannot do

- cannot unlock system drive (unless you create a custom Pre-Boot Authentication image with it; however s3save operation is supported when drive gets unlocked with sedutil's PBA image)
- disk password cannot be read interactively, nor from cmdline argument (however you can encrypt the password file and unlock passphrase is obtained from stdin)
- will not work with CONFIG_BLK_SED_OPAL=n kernel (and is Linux only, but this should be obvious now)


### Building

Just:

```
    make
```

If you need a static binary:

```
    make STATIC=1
```

If you wish to not depend on libargon2 at cost of disabling encrypted password file support (may be combined with STATIC=1):

```
    make ENCRYPTED_PASSWORDS=0
```

If you are Gentoo Linux user, you will find an ebuild in [my overlay](https://github.com/dex6/dexlay).

### Usage

```
    sed-opal-unlocker <operation> <disk_path> <password_file_path>
```

Where:
- `<operation>` is one of: lock, unlock, MBRunshadow, s3save or comma-separated space-less combination of them (except lock)
- `<disk_path>` is device path, eg. /dev/sda, /dev/nvme0n1, etc.
- `<password_file_path>` is path to file containing the disk password; if password file is encrypted, passphrase for decrypting it is read from stdin.

Operation specifies what the tool should do:
- `lock`: lock the drive. Useful mainly for testing.
- `unlock`: unlock the drive. The main feature of this tool.
- `MBRunshadow`: disable MBR shadow image. Use after unlock when the disk has been configured to shadow MBR (see below).
- `s3save`: store password in the Linux kernel for enabling drive unlock after S3 sleep.

When the disk has been initialized with sedutil-cli without using its `-n` option, the password which is send to the disk is a hash calculated using PKBDF2 algorithm from plain text password and the disk serial for salting. In order to use such password with `sed-opal-unlocker`, all you need to do is to store the hashed password in the password file. Fortunately, there's a Python script which will do this for you.

```
    sedutil-passhasher.py <disk_path> <output_passwordhash_file_path> [encrypt_password] [algorithm]
```

You need to call this script once, as root, cause it reads serial number from the disk needed to salt the password for hashing. Plaintext disk password is entered on script standard input. Hashed password (with some magic value for file type recognition) is written to the output file specified by second argument. Note that the file will be overwritten when it exists.

When optional argument, [encrypt_password] is provided and set to 1, the hashed password file will be encrypted using additional "unlock passphrase", also interactively asked on standard input. The unlock passphrase can be optionally salted with current machine's DMI data (serial number or UUID), which makes it usable only on this machine. (This can be hacked around of course, but attacker needs to know this data cause it's not stored in the encrypted password file). When an encrypted password file is provided to sed-opal-unlocker, it will ask for the unlock passphrase on stdin. Note that password encryption currently cannot be used when disk has been initialized without password hashing (sedutil -n).

Please also note that the encrypted password file does not store any authentication/verification data. Had the attacker obtained an encrypted passwordfile, he/she still cannot bruteforce it, cause only the disk can tell whether the unlock passphrase is correct or not. Even having access to the disk does not make bruteforcing easier, cause (a) argon2, (b) OPAL disks have limit how many times you may enter wrong password, and then will require a power-cycle to start talking to you again.

The last optional argument, [algorithm], can be either 'sha1' (default when omitted) or 'sha512'. This should be chosen depending on sedutil version you have used to initialize the drive:
- [original sedutil](https://github.com/Drive-Trust-Alliance/sedutil) uses SHA-1 for hashing passwords and unfortunately its development seems stalled
- [ChubbyAnt fork](https://github.com/ChubbyAnt/sedutil) uses more secure SHA-512 algorithm, has many nice features developed by community and works on modern AMD/Intel systems - check it out!

### Bonus: disk initialization notes

The most helpful information source for me was [Self-Encrypting Drives](https://wiki.archlinux.org/index.php/Self-Encrypting_Drives) article on Archlinux wiki. Another source worth looking at is [sedutil wiki](https://github.com/Drive-Trust-Alliance/sedutil/wiki).

Despite I'm encrypting non-root (secondary) disk, I still prefer to enable MBR shadowing and filling it with zeros. Otherwise when kernel boots and tries to read partition table while the disk is still locked, scary looking IO errors are generated, and disk also saves them in some SMART error counter.

**Please note that tinkering with your drive may cause data loss. It's best to work with an empty drive, so you lose nothing when screwing up. Otherwise, HAVE A BACKUP.**

**Do not execute this for your root drive. It won't boot without a proper PBA image.**

**In all the following examples, replace /dev/disk with proper path (like /dev/sda or /dev/nvme0n1), and "password1234" with your real password.** Non-indented line represents command to be executed, following indented lines are its example output.


1. Initial setup

```
sedutil-cli --initialsetup password1234 /dev/disk
    takeOwnership complete
    Locking SP Activate Complete
    LockingRange0 disabled
    LockingRange0 set to RW
    MBRDone set on
    MBRDone set on
    MBREnable set on
    Initial setup of TPer complete on /dev/disk
```

2. Clear MBR shadow image

(sedutil-cli requires a file to load, therefore first we need to create image filled with zeros. Copying takes a while and it's better not to interrupt it - disk may hang, stop responding and require a power-cycle to recover. The disk may also come with empty PBA already, but I think it's better to write it explicitly.)

```
dd if=/dev/zero of=/tmp/zeros.img bs=1M count=128
    128+0 records in
    128+0 records out
    134217728 bytes (134 MB, 128 MiB) copied, 0,0430394 s, 3,1 GB/s

sedutil-cli --loadPBAimage password1234 /tmp/zeros.img /dev/disk
    Writing PBA to /dev/disk
    ...
    19381540 of 134217728 14% blk=61334
    ...
    112363888 of 134217728 83% blk=61334
    ...
    134217728 of 134217728 100% blk=18936
    PBA image  /tmp/zeros.img written to /dev/disk
```

3. Ensure MBR shadowing is enabled

```
sedutil-cli --setMBREnable on password1234 /dev/disk
    MBRDone set on
    MBREnable set on
```

4. Enable global locking range

```
sedutil-cli --enableLockingRange 0 password1234 /dev/disk
    LockingRange0 enabled ReadLocking,WriteLocking
```

5. Now your drive is configured. It will lock itself after a power cycle. Do it now.

6. After the power cycle, your drive will be locked and empty shadow MBR will be presented. You may verify it:

```
sedutil-cli --query /dev/disk
    ...
    Locking function (0x0002)
        Locked = Y, LockingEnabled = Y, LockingSupported = Y, MBRDone = N, MBREnabled = Y, MediaEncrypt = Y
    ...

sedutil-cli --listLockingRanges password1234 /dev/disk
    Locking Range Configuration for /dev/disk
    LR0 Begin 0 for 0
                RLKEna = Y  WLKEna = Y  RLocked = Y  WLocked = Y
    ...

hexdump -C /dev/disk -n 512
    00000000  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
    *
    00000200
```

7. a) Prepare hashed password file (if you preferred non-hashed password and added `-n` to sedutil-cli calls, skip this step and just write plaintext password to the password file)

```
cd sed-opal-unlocker
./sedutil-passhasher.py /dev/disk /somewhere/safe/mypassword.secret
    Checking /dev/disk...
    Found DISK MODEL with firmware FW_VER and serial b'1234567890           '
    Password hash will be written into /somewhere/safe/mypassword.secret
    Enter SED password for /dev/disk (CTRL+C to quit): <enter password1234>
    Hashed password saved! Protect that file properly (chown/chmod at least).

chmod 400 /somewhere/safe/mypassword.secret
chown root:root /somewhere/safe/mypassword.secret
```

7. b) When deciding to encrypt the hashed password file, it will look like this:

```
cd sed-opal-unlocker
./sedutil-passhasher.py /dev/disk /somewhere/safe/mypassword.secret 1
    Checking /dev/disk...
    Found DISK MODEL with firmware FW_VER and serial b'1234567890           '
    Encrypted password hash will be written into /somewhere/safe/mypassword.secret
    Argon2id CPU cost = 13 iterations
    Argon2id MEM cost = 341.375 MB
    Argon2id threads  = 4
    Enter SED password for /dev/disk (CTRL+C to quit): <enter password1234>
    Enter passphrase for unlocking encrypted passwordhash file: <enter unlock passphrase>
    Enter passphrase again for verification: <enter unlock passphrase again>
    Use DMI data to generate passphrase salt?
    If you say Y, the passphrase will work only on this system. [y/n]: <enter "y" or "n">
    Hashed password saved! Protect that file properly (chown/chmod at least).

chmod 400 /somewhere/safe/mypassword.secret
chown root:root /somewhere/safe/mypassword.secret
```

8. a) Now, finally, use the sed-opal-unlocker to unlock the drive:

```
cd sed-opal-unlocker
./sed-opal-unlocker unlock,MBRunshadow /dev/disk /somewhere/safe/mypassword.secret
```

If no errors were printed, it worked! Check yourself with commands from step 6. Chaining both operations together instead of separate two calls is especially useful when using encrypted password hash files - you wouldn't need to enter the passphrase twice.

8. b) If you're interested as well (or only) in S3 sleep support:

```
cd sed-opal-unlocker
./sed-opal-unlocker s3save /dev/disk /somewhere/safe/mypassword.secret
```

9. You may put 8a / 8b commands in some initialization scripts, initramfs, etc. Writing a `.service` file should be fairly trivial. Integrating encrypted password files with "plymouth ask-for-password" should be also pretty trivial. Good luck and have fun!
