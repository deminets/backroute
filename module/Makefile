
obj-m += xt_BACKROUTE.o
xt_BACKROUTE-y := xt_BACKROUTE_core.o

KDIR := /lib/modules/$(shell uname -r)/build
MOD_NAME := xt_BACKROUTE.ko

PHONY := all
all: build


PHONY += build
build:
	make -C $(KDIR) M=$(PWD) modules


ifneq ($(filter install,$(MAKECMDGOALS))$(filter remove,$(MAKECMDGOALS)),)
INSTALL_DIR := $(dir $(filter-out filename:,$(shell modinfo ip_tables | grep "filename:")))
$(info INSTALL_DIR = $(INSTALL_DIR))
ifeq ($(INSTALL_DIR),)
$(error INSTALL_DIR not found !!!)
endif
endif
PHONY += install
install: build
	cp -f ./$(MOD_NAME) $(INSTALL_DIR)$(MOD_NAME) && depmod

PHONY += remove
remove:
	rm -f $(INSTALL_DIR)$(MOD_NAME) && depmod


PHONY += clean
clean:
	make -C $(KDIR) M=$(PWD) clean


.DEFAULT:
	$(warning !!!WARNING!!!: not found rule for target = '$(@)')
	@:

.PHONY : $(PHONY)
