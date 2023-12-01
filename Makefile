$(info ################# START MAKEFILE #################)
.DEFAULT_GOAL := all
# =============================================
# PATHs
ROOT_DIR := $(CURDIR)
BUILD_DIR := $(ROOT_DIR)/build
OBJ_DIR := $(BUILD_DIR)/obj
BIN_DIR := $(BUILD_DIR)/bin
LIB_DIR := $(BUILD_DIR)/lib
INC_DIR := $(BUILD_DIR)/include
# =============================================
CC		:= gcc
CP		:= g++
LD		:= ld
ECHO	:= echo -e
PRINTF	:= printf
RM		:= rm
MAKE	:= make
# =============================================
# BASH colors
CLBB:=\\033[1;39m
CLNB:=\\033[0;39m
CLRD:=\\033[0;31m
CLGR:=\\033[0;32m
CLNO:=\\033[0m
CLBL:=\\033[0;34m
CLCY:=\\033[0;36m
CLBO:=\\033[1m

CM:=$(CLGR)
CN:=$(CLNO)
# =============================================

define CURMKFPATH
$(abspath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
endef

define CURMKFDIR
$(notdir $(abspath $(dir $(abspath $(lastword $(MAKEFILE_LIST))))))
endef

define WILDCARD
$(wildcard $(call CURMKFPATH)/$(1)/*.$(2))
endef

define TREEDIR
$(strip $(foreach dir,$(wildcard $(1)/*),$(if $(strip $(wildcard $(dir)/*)),$(dir) $(call TREEDIR,$(dir)))))
endef

# INCLUDE Makefile
INCLUDE_submkf := $(dir $(strip $(foreach it,$(call TREEDIR,$(ROOT_DIR)),$(wildcard $(it)/Makefile))))
#$(info INCLUDE_makefiles = $(INCLUDE_submkf))


# Цель по умолчанию, вызывается на все не описанные цели.
.DEFAULT:
#	$(warning !!!WARNING!!!: not found rule for target = '$(@)')
	@for dir in $(INCLUDE_submkf) ; do cd $$dir ; $(MAKE) $(@) ; cd - ; done
	@:

# Абстрактные цели
.PHONY : $(PHONY)

# $(info MYMAKEGOALS = $(MYMAKEGOALS))
$(info ################## END MAKEFILE ##################)

