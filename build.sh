#!/bin/sh
DATETIME=$(date "+%d.%m.%y-%H:%M")

if cp "$1" target/usr/share/deviceinfo/deviceinfo; then
    cd target
    find . | cpio --create --format='newc' > "../initramfs-$DATETIME.cpio"
    rm usr/share/deviceinfo/deviceinfo
    cd ..
    gzip -9 "initramfs-$DATETIME.cpio"
else
    echo "Error: Failed to copy $1" >&2
    exit 1
fi
