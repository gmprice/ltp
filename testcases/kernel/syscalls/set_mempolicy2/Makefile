# SPDX-License-Identifier: GPL-2.0-or-later
top_srcdir		?= ../../../..

LTPLIBS = ltpnuma

include $(top_srcdir)/include/mk/testcases.mk

NEEDS_LIBS = set_mempolicy201 set_mempolicy202 set_mempolicy203 set_mempolicy204 set_mempolicy205 set_mempolicy206 set_mempolicy207

$(NEEDS_LIBS): LDLIBS  += $(NUMA_LIBS)
$(NEEDS_LIBS): LTPLDLIBS = -lltpnuma

include $(top_srcdir)/include/mk/generic_leaf_target.mk
