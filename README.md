# Initramfs for CitrOS

This is a basic initramfs. It's a stripped down version of the postmarketOS initramfs adapted for the needs of running different OS types on obsolete android phones.

It will use the `rootfs=` kernel commandline param to decide what to do. If it has the form `/dev/mmcblkXpY` it will simply mount it as the rootfs and switchroot to it. If it is of the form `/dev/mmcblkXpYpZ`, meaning that a complete disk was flashed to an existing android partition, it will invoke `kpartx` to map the subpartitions, then mount the root filesystem and switchroot to it.

When using `bootpart=`, it will mount the `/dev/mmcblkXpY` device mentioned on `/boot` as well.

## Building for a device

The `devices` directory contains deviceinfo files to be used in order to build the initramfs. You are welcome to submit more.
Just type `./build.sh devices/your-device-of-choice` to get a .cpio.gz file that you can use as an initramfs.

## Modifying

Just modify any files in the target directory and build afterwards.

## Accessing the debug shell through usb

The initramfs configures networking over usb. Your host will receive a specific ip address `172.16.42.2`.
You can use telnet to open the debug shell from your computer.

```bash
telnet 172.16.42.1
```
