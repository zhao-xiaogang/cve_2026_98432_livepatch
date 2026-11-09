obj-m += fix_cve_2026_98432.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean

install: all
	install -D -m 0644 fix_cve_2026_98432.ko /lib/modules/`uname -r`/extra/fix_cve_2026_98432.ko
	depmod -a `uname -r`
	modprobe fix_cve_2026_98432
	cat /sys/kernel/livepatch/fix_cve_2026_98432/enabled
	echo fix_cve_2026_98432 > /etc/modules-load.d/fix_cve_2026_98432.conf

uninstall:
	echo 0 > /sys/kernel/livepatch/fix_cve_2026_98432/enabled
	for i in `seq 1 30`; do \
		[ "`cat /sys/module/fix_cve_2026_98432/refcnt`" = 0 ] && break; \
		sleep 1; \
	done
	rmmod fix_cve_2026_98432
	rm /lib/modules/`uname -r`/extra/fix_cve_2026_98432.ko
	rm -f /etc/modules-load.d/fix_cve_2026_98432.conf
	depmod -a `uname -r`

