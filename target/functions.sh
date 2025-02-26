#!/bin/sh
# This file will be in /init_functions.sh inside the initramfs.

# clobbering variables by not setting them if they have
# a value already!
CONFIGFS="/config/usb_gadget"
CONFIGFS_ACM_FUNCTION="acm.usb0"
CONFIGFS_MASS_STORAGE_FUNCTION="mass_storage.0"
HOST_IP="${unudhcpd_host_ip:-172.16.42.1}"

deviceinfo_getty="${deviceinfo_getty:-}"
deviceinfo_name="${deviceinfo_name:-}"
deviceinfo_codename="${deviceinfo_codename:-}"

get_kernel_param() {
    local param="$1"
    sed -n "s/.*\b${param}=\([^ ]*\).*/\1/p" /proc/cmdline
}

mount_subpartitions() {
    local superpartition
    superpartition=$(get_kernel_param "superpartition")
    sleep 5
    local rootfs_subpartition
    rootfs_subpartition=$(get_kernel_param "rootfs_subpartition")

    echo "Attempting to map subpartitions of $superpartition"

    kpartx -afs "$superpartition"

    echo "Attempting to mount /dev/mapper/$rootfs_subpartition"
    mount "/dev/mapper/$rootfs_subpartition" /sysroot
    sleep 5
}

# Redirect stdout and stderr to logfile
setup_log() {
    local console
    console="$(cat /sys/devices/virtual/tty/console/active)"

    # Stash fd1/2 so we can restore them before switch_root, but only if the
    # console is not null
    if [ -n "$console" ] ; then
        # The kernel logs go to the console, and we log to the kernel. Avoid printing everything
        # twice.
        console="/dev/null"
        exec 3>&1 4>&2
    else
        # Setting console=null is a trick used on quite a few citros devices. However it is generally a really
        # bad idea since it makes it impossible to debug kernel panics, and it makes our job logging in the
        # initramfs a lot harder. We ban this in pmaports but some (usually android) bootloaders like to add it
        # anyway. We ought to have some special handling here to use /dev/zero for stdin instead
        # to avoid weird bugs in daemons that read from stdin (e.g. syslog)
        # See related: https://gitlab.postmarketos.org/citrOS/pmaports/-/issues/2989
        console="/dev/$(echo "$deviceinfo_getty" | cut -d';' -f1)"
        if ! [ -e "$console" ]; then
            console="/dev/null"
        fi
    fi

    # Disable kmsg ratelimiting for userspace (it gets re-enabled again before switch_root)
    echo on > /proc/sys/kernel/printk_devkmsg

    # Spawn syslogd to log to the kernel
    # syslog will try to read from stdin over and over which can pin a cpu when stdin is /dev/null
    # By connecting /dev/zero to stdin/stdout/stderr, we make sure that syslogd
    # isn't blocked when a console isn't available.
    syslogd -K < /dev/zero >/dev/zero 2>&1

    local pmsg="/dev/pmsg0"

    if ! [ -e "$pmsg" ]; then
        pmsg="/dev/null"
    fi

    # Redirect to a subshell which outputs to the logfile as well
    # as to the kernel ringbuffer and pstore (if available).
    # Process substitution is technically non-POSIX, but is supported by busybox
    # shellcheck disable=SC3001
    exec > >(tee /citronics_init.log "$pmsg" "$console" | logger -t "$LOG_PREFIX" -p user.info) 2>&1
}

mount_proc_sys_dev() {
    # mdev
    mount -t proc -o nodev,noexec,nosuid proc /proc || echo "Couldn't mount /proc"
    mount -t sysfs -o nodev,noexec,nosuid sysfs /sys || echo "Couldn't mount /sys"
    mount -t devtmpfs -o mode=0755,nosuid dev /dev || echo "Couldn't mount /dev"
    mount -t tmpfs -o nosuid,nodev,mode=0755 run /run || echo "Couldn't mount /run"

    mkdir /config
    mount -t configfs -o nodev,noexec,nosuid configfs /config

    # /dev/pts (needed for telnet)
    mkdir -p /dev/pts
    mount -t devpts devpts /dev/pts

    # This is required for process substitution to work (as used in setup_log())
    ln -s /proc/self/fd /dev/fd
}

setup_firmware_path() {
    # Add the citrOS-specific path to the firmware search paths.
    # This should be sufficient on kernel 3.10+, before that we need
    # the kernel calling udev (and in our case /usr/lib/firmwareload.sh)
    # to load the firmware for the kernel.
    SYS=/sys/module/firmware_class/parameters/path
    if ! [ -e "$SYS" ]; then
        echo "Kernel does not support setting the firmware image search path. Skipping."
        return
    fi
    # shellcheck disable=SC3037
    echo -n /lib/firmware/ >$SYS
}

setup_mdev() {
    # Start mdev daemon
    mdev -d
}

load_modules() {
	local file="$1"
	local modules="$2"
	[ -f "$file" ] && modules="$modules $(grep -v ^\# "$file")"
	modprobe -a $modules
}

fail_halt_boot() {
    debug_shell
    echo "Looping forever"
    while true; do
        sleep 1
    done
}

debug_shell() {
    echo "Entering debug shell"

    # mount pstore, if possible
    if [ -d /sys/fs/pstore ]; then
        mount -t pstore pstore /sys/fs/pstore || true
    fi

    mount -t debugfs none /sys/kernel/debug || true
    # make a symlink like Android recoveries do
    ln -s /sys/kernel/debug /d

    setup_usb_network
    start_unudhcpd

	cat <<-EOF > /README
	citrOS debug shell

	  Device: $deviceinfo_name ($deviceinfo_codename)
	  Kernel: $(uname -r)
	  OS ver: $VERSION
	  initrd: $INITRAMFS_PKG_VERSION

	Read the initramfs log with 'cat /citros_init.log'.
	EOF

	# Display some info
	cat <<-EOF > /etc/profile
	cat /README
	. /functions.sh
	EOF

	cat <<-EOF > /sbin/citros_getty
	#!/bin/sh
	/bin/sh -l
	EOF
	chmod +x /sbin/citros_getty

	cat <<-EOF > /sbin/citros_logdump
	#!/bin/sh
	echo "Dumping logs, check for a new mass storage device"
	touch /tmp/dump_logs
	EOF
	chmod +x /sbin/citros_logdump

    # Get the console (ttyX) associated with /dev/console
    local active_console
    active_console="$(cat /sys/devices/virtual/tty/tty0/active)"
    # Get a list of all active TTYs include serial ports
    local serial_ports
    serial_ports="$(cat /sys/devices/virtual/tty/console/active)"
    # Get the getty device too (might not be active)
    local getty
    getty="$(echo "$deviceinfo_getty" | cut -d';' -f1)"

    # Run getty's on the consoles
    for tty in $serial_ports; do
        # Some ports we handle explicitly below to make sure we don't
        # accidentally spawn two getty's on them
        if echo "tty0 tty1 ttyGS0 $getty" | grep -q "$tty" ; then
            continue
        fi
        run_getty "$tty"
    done

    if [ -n "$getty" ]; then
        run_getty "$getty"
    fi

    # Rewrite tty to tty1 if tty0 is active
    if [ "$active_console" = "tty0" ]; then
        active_console="tty1"
    fi

    # Getty on the display
    run_getty "$active_console"

    # And on the usb acm port (if it exists)
    if [ -e /dev/ttyGS0 ]; then
        run_getty ttyGS0
    fi

    setup_usb_configfs_udc
    # Spawn telnetd for those who prefer it. ACM gadget mode is not
    # supported on some old kernels so this exists as a fallback.
    telnetd -b "${HOST_IP}:23" -l /sbin/citros_getty &
}

setup_usb_network() {
	# Only run once
	_marker="/tmp/_setup_usb_network"
	[ -e "$_marker" ] && return
	touch "$_marker"
	echo "Setup usb network"
	modprobe libcomposite
	setup_usb_network_configfs
}

setup_usb_network_configfs() {
	# See: https://www.kernel.org/doc/Documentation/usb/gadget_configfs.txt
	local skip_udc="$1"

	if ! [ -e "$CONFIGFS" ]; then
		echo "$CONFIGFS does not exist, skipping configfs usb gadget"
		return
	fi

	if [ -z "$(get_usb_udc)" ]; then
		echo "  No UDC found, skipping usb gadget"
		return
	fi

	# Default values for USB-related deviceinfo variables
	usb_idVendor="${deviceinfo_usb_idVendor:-0x18D1}"   # default: Google Inc.
	usb_idProduct="${deviceinfo_usb_idProduct:-0xD001}" # default: Nexus 4 (fastboot)
	usb_serialnumber="${deviceinfo_usb_serialnumber:-postmarketOS}"
	usb_network_function="${deviceinfo_usb_network_function:-ncm.usb0}"
	usb_network_function_fallback="rndis.usb0"

	echo "  Setting up USB gadget through configfs"
	# Create an usb gadet configuration
	mkdir $CONFIGFS/g1 || echo "  Couldn't create $CONFIGFS/g1"
	echo "$usb_idVendor"  > "$CONFIGFS/g1/idVendor"
	echo "$usb_idProduct" > "$CONFIGFS/g1/idProduct"

	# Create english (0x409) strings
	mkdir $CONFIGFS/g1/strings/0x409 || echo "  Couldn't create $CONFIGFS/g1/strings/0x409"

	# shellcheck disable=SC2154
	echo "$deviceinfo_manufacturer" > "$CONFIGFS/g1/strings/0x409/manufacturer"
	echo "$usb_serialnumber"        > "$CONFIGFS/g1/strings/0x409/serialnumber"
	# shellcheck disable=SC2154
	echo "$deviceinfo_name"         > "$CONFIGFS/g1/strings/0x409/product"

	# Create network function.
	if ! mkdir $CONFIGFS/g1/functions/"$usb_network_function"; then
		# Try the fallback function next
		if mkdir $CONFIGFS/g1/functions/"$usb_network_function_fallback"; then
			usb_network_function="$usb_network_function_fallback"
		fi
	fi

	# Create configuration instance for the gadget
	mkdir $CONFIGFS/g1/configs/c.1 \
		|| echo "  Couldn't create $CONFIGFS/g1/configs/c.1"
	mkdir $CONFIGFS/g1/configs/c.1/strings/0x409 \
		|| echo "  Couldn't create $CONFIGFS/g1/configs/c.1/strings/0x409"
	echo "USB network" > $CONFIGFS/g1/configs/c.1/strings/0x409/configuration \
		|| echo "  Couldn't write configration name"

	# Link the network instance to the configuration
	ln -s $CONFIGFS/g1/functions/"$usb_network_function" $CONFIGFS/g1/configs/c.1 \
		|| echo "  Couldn't symlink $usb_network_function"

	# If an argument was supplied then skip writing to the UDC (only used for mass storage
	# log recovery)
	if [ -z "$skip_udc" ]; then
		setup_usb_configfs_udc
	fi
}

start_unudhcpd() {
	# Only run once
	[ "$(pidof unudhcpd)" ] && return

	# Skip if disabled
	# shellcheck disable=SC2154
	if [ "$deviceinfo_disable_dhcpd" = "true" ]; then
		return
	fi

	local client_ip="${unudhcpd_client_ip:-172.16.42.2}"
	echo "Starting unudhcpd with server ip $HOST_IP, client ip: $client_ip"

	# Get usb interface
	usb_network_function="${deviceinfo_usb_network_function:-ncm.usb0}"
	usb_network_function_fallback="rndis.usb0"
	if [ -n "$(cat $CONFIGFS/g1/UDC)" ]; then
		INTERFACE="$(
			cat "$CONFIGFS/g1/functions/$usb_network_function/ifname" 2>/dev/null ||
			cat "$CONFIGFS/g1/functions/$usb_network_function_fallback/ifname" 2>/dev/null ||
			echo ''
		)"
	else
		INTERFACE=""
	fi
	if [ -n "$INTERFACE" ]; then
		ifconfig "$INTERFACE" "$HOST_IP"
	elif ifconfig rndis0 "$HOST_IP" 2>/dev/null; then
		INTERFACE=rndis0
	elif ifconfig usb0 "$HOST_IP" 2>/dev/null; then
		INTERFACE=usb0
	elif ifconfig eth0 "$HOST_IP" 2>/dev/null; then
		INTERFACE=eth0
	fi

	if [ -z "$INTERFACE" ]; then
		echo "  Could not find an interface to run a dhcp server on"
		echo "  Interfaces:"
		ip link
		return
	fi

	echo "  Using interface $INTERFACE"
	echo "  Starting the DHCP daemon"
	(
		unudhcpd -i "$INTERFACE" -s "$HOST_IP" -c "$client_ip"
	) &
}

setup_usb_configfs_udc() {
    # Check if there's an USB Device Controller
    local _udc_dev
    _udc_dev="$(get_usb_udc)"

    # Remove any existing UDC to avoid "write error: Resource busy" when setting UDC again
    if [ "$(wc -w <$CONFIGFS/g1/UDC)" -gt 0 ]; then
        echo "" > "$CONFIGFS"/g1/UDC || echo "  Couldn't write to clear UDC"
    fi
    # Link the gadget instance to an USB Device Controller. This activates the gadget.
    # See also: https://gitlab.postmarketos.org/citrOS/pmbootstrap/issues/338
    echo "$_udc_dev" > "$CONFIGFS"/g1/UDC || echo "  Couldn't write new UDC"
}

get_usb_udc() {
    local _udc_dev="${deviceinfo_usb_network_udc:-}"
    if [ -z "$_udc_dev" ]; then
        # shellcheck disable=SC2012
        _udc_dev=$(ls /sys/class/udc | head -1)
    fi

    echo "$_udc_dev"
}

run_getty() {
    {
        # Due to how the Linux host ACM driver works, we need to wait
        # for data to be sent from the host before spawning the getty.
        # Otherwise our README message will be echo'd back all garbled.
        # On Linux in particular, there is a hack we can use: by writing
        # something to the port, it will be echo'd back at the moment the
        # port on the host side is opened, so user input won't even be
        # needed in most cases. For more info see the blog posts at:
        # https://michael.stapelberg.ch/posts/2021-04-27-linux-usb-virtual-serial-cdc-acm/
        # https://connolly.tech/posts/2024_04_15-broken-connections/
        if [ "$1" = "ttyGS0" ]; then
            echo " " > /dev/ttyGS0
            # shellcheck disable=SC3061
            read -r < /dev/ttyGS0
        fi
        while /sbin/getty -n -l /sbin/citros_getty "$1" 115200 vt100; do
            sleep 0.2
        done
    } &
}

restore_consoles() {
    # Restore stdout and stderr to their original values if they
    # were stashed
    if [ -e "/proc/1/fd/3" ]; then
        exec 1>&3 2>&4
    elif ! grep -q "citronics.debug-shell" /proc/cmdline; then
        echo "$LOG_PREFIX Disabling console output again (use 'citronics.debug-shell' to keep it enabled)"
        exec >/dev/null 2>&1
    fi

    echo ratelimit > /proc/sys/kernel/printk_devkmsg
}

map_subpartitions() {
    local rootfs
    rootfs=$(get_kernel_param "rootfs")

    # Remove the /dev/ prefix if present
    rootfs=${rootfs#/dev/}

    # Check if rootfs is in the form mmcblkXpYpZ
    if echo "$rootfs" | grep -qE '^mmcblk[0-9]+p[0-9]+p[0-9]+$'; then
        # Extract mmcblkXpY from mmcblkXpYpZ
        local superpartition
        superpartition=$(echo "$rootfs" | grep -oE '^mmcblk[0-9]+p[0-9]+')
        echo "Mapping subpartitions of $superpartition"

        # Wait for the superpartition to be available, with a timeout of 10 seconds
        local root_partition="/dev/$superpartition"
        local timeout=10
        while [ ! -e "$root_partition" ] && [ $timeout -gt 0 ]; do
            echo "Waiting for $root_partition to be available..."
            sleep 1
            timeout=$((timeout - 1))
        done

        if [ -e "$root_partition" ]; then
            kpartx -afs "$root_partition"
            # Create symbolic links in /dev/ for each device in /dev/mapper/
            for dev in /dev/mapper/${superpartition}p*; do
                ln -s "$dev" "/dev/$(basename "$dev")"
            done
        else
            echo "Device $root_partition not available after 10 seconds, skipping mapping."
        fi
    else
        echo "No subpartitions to map for $rootfs"
    fi
}

mount_rootfs() {
    local rootfs
    rootfs=$(get_kernel_param "rootfs")

    # Remove the /dev/ prefix if present
    rootfs=${rootfs#/dev/}

    # Wait for the rootfs device to be available, with a timeout of 10 seconds
    local rootfs_device="/dev/$rootfs"
    local timeout=10
    while [ ! -e "$rootfs_device" ] && [ $timeout -gt 0 ]; do
        echo "Waiting for $rootfs_device to be available..."
        sleep 1
        timeout=$((timeout - 1))
    done

    if [ -e "$rootfs_device" ]; then
        mount "$rootfs_device" /sysroot
    else
        echo "Device $rootfs_device not available after 10 seconds, cannot mount rootfs."
    fi
}