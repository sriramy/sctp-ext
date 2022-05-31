# SPDX-License-Identifier: GPL-2.0
KVER := linux-5.17.8
KSRC := $(HOME)/xc/linux/$(KVER)
KOBJ := $(HOME)/xc/workspace/xcluster/obj-sctp

all::
	$(MAKE) -C $(KSRC) O=$(KOBJ) M=`pwd`

clean::
	$(MAKE) -C $(KSRC) O=$(KOBJ) M=`pwd` $@
