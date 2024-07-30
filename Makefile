MAKEFILE_DIR:=$(dir $(realpath $(firstword $(MAKEFILE_LIST))))
MDIR ?= /lib/modules/$(shell uname -r)
KDIR ?= $(MDIR)/build
MODULE = unlockhibernate
MODULE_OBJ = $(MODULE).ko
VERSION = 0.01
DKMS_PATH = /usr/src/unlockhibernate-$(VERSION)/

.PHONY: clean rmmod insmod install quickInstall

all:
	$(MAKE) -C $(KDIR) M=$(MAKEFILE_DIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(MAKEFILE_DIR) clean

sign: all
	sudo $(MDIR)/source/scripts/sign-file sha256 \
		/usr/src/certs/signing_key.pem /usr/src/certs/signing_key.pem ${MODULE_OBJ}

rmmod:
	echo 0 | sudo tee /sys/kernel/livepatch/unlockhibernate/enabled || true
	lsmod | grep -q "^$(MODULE)\s" && sudo rmmod $(MODULE) || true

insmod: all sign rmmod
	sudo insmod ./$(MODULE_OBJ)

install:
	$(MAKE) -C $(KDIR) M=$(MAKEFILE_DIR) modules_install

quickInstall:
	cp $(MODULE_OBJ) $(MDIR)/extra

dkmsUninstall:
	sudo dkms remove -m $(MODULE) -v $(VERSION) --all || true
	sudo rm -fr $(DKMS_PATH)

dkmsInstall: dkmsUninstall
	sudo mkdir -p $(DKMS_PATH)
	sudo cp Kbuild dkms.conf Makefile mod.c $(DKMS_PATH)
	sudo dkms add -m $(MODULE) -v $(VERSION)
	sudo dkms install $(MODULE)/$(VERSION)

