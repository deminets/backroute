CFLAGS = -O2 -Wall
NAME = BACKROUTE
LIBNAME = libxt_${NAME}.so


PHONY := all
all: ${LIBNAME}

lib%.so: lib%.c.o
	gcc -shared -fPIC -o $@ $^;

lib%.c.o: lib%.c
	gcc ${CFLAGS} -fPIC -c -o $@ $<;


ifneq ($(filter install,$(MAKECMDGOALS))$(filter remove,$(MAKECMDGOALS)),)
INSTALL_DIR := $(sort $(dir $(shell find /usr/ -wholename "*/xtables/libipt_*.so" 2>/dev/null )) $(dir $(shell find /usr/ -wholename "*/xtables/libxt_*.so" 2>/dev/null )))
$(info INSTALL_DIR = $(INSTALL_DIR))
ifeq ($(INSTALL_DIR),)
$(error INSTALL_DIR not found !!!)
endif
endif
PHONY += install
install: ${LIBNAME}
	@echo cp -f ./${LIBNAME} $(INSTALL_DIR)${LIBNAME}


PHONY += remove
remove:
	echo rm -f $(INSTALL_DIR)${LIBNAME}


PHONY += clean
clean:
	rm -f *.c.o ${LIBNAME}


.DEFAULT:
	$(warning !!!WARNING!!!: not found rule for target = '$(@)')
	@:

.PHONY : $(PHONY)
