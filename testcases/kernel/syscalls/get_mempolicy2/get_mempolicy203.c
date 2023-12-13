// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Gregory Price <gregory.price@memverge.com>
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
 * Verify that get_mempolicy() returns a proper return value and errno for various cases.
 */

#include "config.h"
#include "tst_test.h"

#ifdef HAVE_NUMA_V2
#include <numa.h>
#include <numaif.h>
#include <errno.h>
#include <stdbool.h>
#include "tst_numa.h"
#include "get_mempolicy.h"

#define MPOL_WEIGHTED_INTERLEAVE 6

#define MEM_LENGTH	(4 * 1024 * 1024)
#define PAGES_ALLOCATED 16u

#define POLICY_DESC(x,y) .mode = x, .mode_flags = y, .desc = "policy: "#x

static struct tst_nodemap *node;
static struct bitmask *nodemask, *getnodemask, *empty_nodemask;
unsigned char *exp_weights = NULL, *get_weights = NULL;

struct test_case {
	uint16_t mode;
	uint16_t mode_flags;
	const char *desc;
	unsigned int flags;
	char *addr;
	int (*set_pol)(struct test_case *tc);
	struct bitmask **exp_nodemask;
	bool local_weights;
};

static int test_set_weighted_interleave_global(struct test_case *tc);
static int test_set_weighted_interleave_local(struct test_case *tc);

static struct test_case tcase[] = {
	{
		POLICY_DESC(MPOL_WEIGHTED_INTERLEAVE, 0),
		.set_pol = test_set_weighted_interleave_global,
		.exp_nodemask = &nodemask,
		.local_weights = false,
	},
	{
		POLICY_DESC(MPOL_WEIGHTED_INTERLEAVE, 0),
		.set_pol = test_set_weighted_interleave_local,
		.exp_nodemask = &nodemask,
		.local_weights = true,
	},
};

static int test_set_weighted_interleave_global(struct test_case *tc)
{
	TEST(set_mempolicy2(tc->mode, tc->mode_flags, nodemask->maskp, nodemask->size, NULL));
	return TST_RET;
}

static int test_set_weighted_interleave_local(struct test_case *tc)
{
	TEST(set_mempolicy2(tc->mode, tc->mode_flags, nodemask->maskp, nodemask->size, exp_weights));
	return TST_RET;
}

static void setup(void)
{
	int i;

	node = tst_get_nodemap(TST_NUMA_MEM, PAGES_ALLOCATED * getpagesize() / 1024);
	if (node->cnt < 1)
		tst_brk(TCONF, "test requires at least one NUMA memory node");

	nodemask = numa_allocate_nodemask();
	empty_nodemask = numa_allocate_nodemask();
	getnodemask = numa_allocate_nodemask();
	numa_bitmask_setbit(nodemask, node->map[0]);
	numa_bitmask_setbit(nodemask, node->map[1]);

	get_weights = malloc(getnodemask->size);
	exp_weights = malloc(getnodemask->size);
	memset(get_weights, 0xff, getnodemask->size);
	memset(exp_weights, 1, getnodemask->size);
	for (i = 0; i < numa_num_configured_nodes(); i++)
		exp_weights[i] = (i % 255) + 2;
}

static void cleanup(void)
{
	numa_free_nodemask(nodemask);
	numa_free_nodemask(getnodemask);
	tst_nodemap_free(node);
	free(exp_weights);
	free(get_weights);
	exp_weights = NULL;
	get_weights = NULL;
}

int compare_weights(bool local_weights)
{
	for (int i = 0; i < numa_num_configured_nodes(); i++) {
		/* In the case of global weights, should be all 1s */
		unsigned char weight = local_weights ? exp_weights[i] : 1;
		if (get_weights[i] != weight)
			return -1;
	}
	return 0;
}

static void do_test(unsigned int i)
{
	struct test_case *tc = &tcase[i];
	struct mpol_args args;

	if (tc->set_pol && tc->set_pol(tc))
		tst_brk(TFAIL | TERRNO, "test #%d: set_mempolicy() failed", i+1);

	tst_res(TINFO, "test #%d: %s", i+1, tc->desc);

	args.pol_nodes = (uint64_t)getnodemask->maskp;
	args.il_weights = (uint64_t)get_weights;
	args.pol_maxnodes = getnodemask->size;

	TST_EXP_PASS(get_mempolicy2(&args, 0, 0), "%s", tc->desc);

	struct bitmask *exp_mask = *(tc->exp_nodemask);

	if (args.mode == MPOL_WEIGHTED_INTERLEAVE)
		tst_res(TPASS, "policy correct");
	else
		tst_res(TFAIL, "policy incorrect");

	if (!numa_bitmask_equal(exp_mask, getnodemask)) {
		tst_res(TFAIL, "masks are not equal");
		tst_res_hexd(TINFO, exp_mask->maskp,
			     exp_mask->size / 8, "expected:");
		tst_res_hexd(TINFO, getnodemask->maskp,
			     getnodemask->size / 8, "returned:");
	}

	if (compare_weights(tc->local_weights))
		tst_res(TFAIL, "weight are incorrect");
	else
		tst_res(TPASS, "weights are correct");
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
