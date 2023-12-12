// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2020 Petr Vorel <pvorel@suse.cz>
 * Copyright (c) Linux Test Project, 2009-2020
 * Copyright (c) Crackerjack Project, 2007-2008, Hitachi, Ltd
 *
 * Authors:
 * Takahiro Yasui <takahiro.yasui.mp@hitachi.com>
 * Yumiko Sugita <yumiko.sugita.yf@hitachi.com>
 * Satoshi Fujiwara <sa-fuji@sdl.hitachi.co.jp>
 * Manas Kumar Nayak <maknayak@in.ibm.com> (original port to the legacy API)
 */

/*\
 * [Description]
 *
 * Verify that get_mempolicy() returns a proper return errno for failure cases.
 */

#include "config.h"
#include "tst_test.h"

#ifdef HAVE_NUMA_V2
#include <numa.h>
#include <numaif.h>
#include <errno.h>
#include "tst_numa.h"
#include "get_mempolicy.h"

#define PAGES_ALLOCATED 16u

#define POLICY_DESC_TEXT(x, y) .policy = x, .desc = "policy: "#x", "y

static struct tst_nodemap *node;
static struct bitmask *nodemask;

struct test_case {
	int policy;
	const char *desc;
	unsigned int flags;
	int err;
	char *addr;
};

static struct test_case tcase[] = {
	{
		POLICY_DESC_TEXT(MPOL_DEFAULT, "invalid address"),
		.addr = NULL,
		.err = EFAULT,
		.flags = MPOL_F_ADDR,
	},
	{
		POLICY_DESC_TEXT(MPOL_DEFAULT, "invalid flags, no target"),
		.err = EINVAL,
		.flags = -1,
	},
};

static void setup(void)
{
	node = tst_get_nodemap(TST_NUMA_MEM, PAGES_ALLOCATED * getpagesize() / 1024);
	if (node->cnt < 1)
		tst_brk(TCONF, "test requires at least one NUMA memory node");

	nodemask = numa_allocate_nodemask();
}

static void cleanup(void)
{
	numa_free_nodemask(nodemask);
	tst_nodemap_free(node);
}

static void do_test(unsigned int i)
{
	struct test_case *tc = &tcase[i];
	struct mpol_args args;
	int addr_node;
	int *addr_node_ptr;

	args.pol_nodes = (uint64_t)nodemask->maskp;
	args.il_weights = (uint64_t)NULL;
	args.pol_maxnodes = nodemask->size;

	addr_node_ptr = (tc->flags & MPOL_F_ADDR) ? &addr_node : NULL;

	TST_EXP_FAIL(get_mempolicy2(&args, (uint64_t)tc->addr, addr_node_ptr,
				    tc->flags), tc->err, "%s", tc->desc);
}

static struct tst_test test = {
	.tcnt = ARRAY_SIZE(tcase),
	.test = do_test,
	.setup = setup,
	.cleanup = cleanup,
};

#else
TST_TEST_TCONF(NUMA_ERROR_MSG);
#endif /* HAVE_NUMA_V2 */
