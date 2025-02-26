#!/bin/sh
DATETIME=$(date "+%d.%m.%y-%H:%M")
cd target
find . | cpio --create --format='newc' > ../initramfs-$DATETIME.cpio
cd ..
gzip -9 initramfs-$DATETIME.cpio
