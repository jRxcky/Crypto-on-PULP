
APP = test
APP_SRCS += test.c aes.c

ifdef USE_CLUSTER
APP_CFLAGS += -DCLUSTER -DNUM_CLUSTER=USE_CLUSTER
ifdef NUM_CORES
APP_CFLAGS += -DNUM_CORES=$(NUM_CORES)
else
APP_CFLAGS += -DNUM_CORES=1
endif
endif

ifdef DEBUG
APP_CFLAGS += -DDEBUG
endif

ifdef MEM_SIZE
ifeq ($(MEM_SIZE), 512)
APP_CFLAGS += -DMEM_SIZE=512
endif
ifeq ($(MEM_SIZE), 1)
APP_CFLAGS += -DMEM_SIZE=1
endif
ifeq ($(MEM_SIZE), 2)
APP_CFLAGS += -DMEM_SIZE=2
endif
ifeq ($(MEM_SIZE), 4)
APP_CFLAGS += -DMEM_SIZE=4
endif
ifeq ($(MEM_SIZE), 8)
APP_CFLAGS += -DMEM_SIZE=8
endif
ifeq ($(MEM_SIZE), 16)
APP_CFLAGS += -DMEM_SIZE=16
endif
ifeq ($(MEM_SIZE), 32)
APP_CFLAGS += -DMEM_SIZE=32
endif
endif

APP_CFLAGS += -Os -g
APP_LDFLAGS += -Os -g

include $(RULES_DIR)/pmsis_rules.mk

