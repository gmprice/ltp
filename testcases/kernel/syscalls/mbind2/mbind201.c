// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) Crackerjack Project., 2007-2008, Hitachi, Ltd
 * Copyright (c) 2017 Petr Vorel <pvorel@suse.cz>
 *
 * Authors:
 * Takahiro Yasui <takahiro.yasui.mp@hitachi.com>,
 * Yumiko Sugita <yumiko.sugita.yf@hitachi.com>,
 * Satoshi Fujiwara <sa-fuji@sdl.hitachi.co.jp>
 */

#include <errno.h>
#if HAVE_NUMA_H
#include <numa.h>
#endif

#include "config.h"
#include "numa_helper.h"
#include "tst_test.h"
#include "tst_numa.h"
#include "lapi/numaif.h"
#include "mbind.h"

#define MPOL_WEIGHTED_INTERLEAVE 6

#ifdef HAVE_NUMA_V2

#define MEM_LENGTH (4 * 1024 * 1024)

#define UNKNOWN_POLICY -1

#define POLICY_DESC(x, y) .mode = x, .mode_flags = y, .desc = #x
#define POLICY_DESC_TEXT(x, y, z) .mode = x, .mode_flags = y, .desc = #x" ("z")"

static struct bitmask *nodemask, *getnodemask, *empty_nodemask;

static void test_default(unsigned int i, char *p);
static void test_none(unsigned int i, char *p);
static void test_invalid_nodemask(unsigned int i, char *p);
static void check_mode_pref_or_local(int);

struct test_case {
	unsigned short mode;
	unsigned short mode_flags;
	const char *desc;
	unsigned flags;
	int ret;
	int err;
	void (*check_mode)(int);
	void (*test)(unsigned int, char *);
	struct bitmask **exp_nodemask;
};

static struct test_case tcase[] = {
	{
		POLICY_DESC(MPOL_DEFAULT, 0),
		.ret = 0,
		.err = 0,
		.test = test_none,
		.exp_nodemask = &empty_nodemask,
	},
	{
		POLICY_DESC_TEXT(MPOL_DEFAULT, 0, "target exists"),
		.ret = -1,
		.err = EINVAL,
		.test = test_default,
	},
	{
		POLICY_DESC_TEXT(MPOL_BIND, 0, "no target"),
		.ret = -1,
		.err = EINVAL,
		.test = test_none,
	},
	{
		POLICY_DESC(MPOL_BIND, 0),
		.ret = 0,
		.err = 0,
		.test = test_default,
		.exp_nodemask = &nodemask,
	},
	{
		POLICY_DESC_TEXT(MPOL_INTERLEAVE, 0, "no target"),
		.ret = -1,
		.err = EINVAL,
		.test = test_none,
	},
	{
		POLICY_DESC_TEXT(MPOL_WEIGHTED_INTERLEAVE, 0, "no target"),
		.ret = -1,
		.err = EINVAL,
		.test = test_none,
	},
	{
		POLICY_DESC(MPOL_INTERLEAVE, 0),
		.ret = 0,
		.err = 0,
		.test = test_default,
		.exp_nodemask = &nodemask,
	},
	{
		POLICY_DESC(MPOL_WEIGHTED_INTERLEAVE, 0),
		.ret = 0,
		.err = 0,
		.test = test_default,
		.exp_nodemask = &nodemask,
	},
	{
		POLICY_DESC_TEXT(MPOL_PREFERRED, 0, "no target"),
		.ret = 0,
		.err = 0,
		.test = test_none,
		.check_mode = check_mode_pref_or_local,
	},
	{
		POLICY_DESC(MPOL_PREFERRED, 0),
		.ret = 0,
		.err = 0,
		.test = test_default,
		.exp_nodemask = &nodemask,
	},
	{
		POLICY_DESC(MPOL_LOCAL, 0),
		.ret = 0,
		.err = 0,
		.test = test_none,
		.exp_nodemask = &empty_nodemask,
		.check_mode = check_mode_pref_or_local,
	},
	{
		POLICY_DESC_TEXT(MPOL_LOCAL, 0, "target exists"),
		.ret = -1,
		.err = EINVAL,
		.test = test_default,
	},
	{
		POLICY_DESC(UNKNOWN_POLICY, 0),
		.ret = -1,
		.err = EINVAL,
		.test = test_none,
	},
	{
		POLICY_DESC_TEXT(MPOL_DEFAULT, 0, "invalid flags"),
		.flags = -1,
		.ret = -1,
		.err = EINVAL,
		.test = test_none,
	},
	{
		POLICY_DESC_TEXT(MPOL_PREFERRED, 0, "invalid nodemask"),
		.ret = -1,
		.err = EFAULT,
		.test = test_invalid_nodemask,
	},
};

static void check_mode_pref_or_local(int mode)
{
	if (mode != MPOL_PREFERRED && mode != MPOL_LOCAL) {
		tst_res(TFAIL, "Wrong mode: %s(%d), "
			"expected MPOL_PREFERRED or MPOL_LOCAL",
			tst_mempolicy_mode_name(mode), mode);
	}
}

static void test_default(unsigned int i, char *p)
{
	struct test_case *tc = &tcase[i];

	TEST(mbind2((unsigned long)p, MEM_LENGTH, tc->mode, tc->mode_flags, nodemask->maskp,
		    nodemask->size, NULL, -1, tc->flags));
}

static void test_none(unsigned int i, char *p)
{
	struct test_case *tc = &tcase[i];

	TEST(mbind2((unsigned long)p, MEM_LENGTH, tc->mode, tc->mode_flags, NULL, 0,
		    NULL, -1, tc->flags));
}

static void test_invalid_nodemask(unsigned int i, char *p)
{
	struct test_case *tc = &tcase[i];

	/* use invalid nodemask (64 MiB after heap) */
	TEST(mbind2((unsigned long)p, MEM_LENGTH, tc->mode, tc->mode_flags,
		    sbrk(0) + 64*1024*1024, NUMA_NUM_NODES,
		    NULL, -1, tc->flags));
}

static void setup(void)
{
	if (!is_numa(NULL, NH_MEMS, 1))
		tst_brk(TCONF, "requires NUMA with at least 1 node");
	empty_nodemask = numa_allocate_nodemask();
}

static void setup_node(void)
{
	int test_node = -1;

	if (get_allowed_nodes(NH_MEMS, 1, &test_node) < 0)
		tst_brk(TBROK | TERRNO, "get_allowed_nodes failed");

	nodemask = numa_allocate_nodemask();
	getnodemask = numa_allocate_nodemask();
	numa_bitmask_setbit(nodemask, test_node);
}

static void do_test(unsigned int i)
{
	struct test_case *tc = &tcase[i];
	int mode, fail = 0;
	char *p = NULL;

	tst_res(TINFO, "case %s", tc->desc);

	if (tc->mode == MPOL_LOCAL) {
		if ((tst_kvercmp(5, 14, 0)) >= 0)
			tc->check_mode = NULL;
	}

	setup_node();

	p = SAFE_MMAP(NULL, MEM_LENGTH, PROT_READ | PROT_WRITE, MAP_PRIVATE |
			 MAP_ANONYMOUS, 0, 0);

	tc->test(i, p);

	if (TST_RET >= 0) {
		/* Check mode of the allocated memory */
		TEST(get_mempolicy(&mode, getnodemask->maskp,
				   getnodemask->size, p, MPOL_F_ADDR));
		if (TST_RET < 0) {
			tst_res(TFAIL | TTERRNO, "get_mempolicy failed");
			return;
		}

		if (tc->check_mode)
			tc->check_mode(mode);
		else if (tc->mode != mode) {
			tst_res(TFAIL, "Wrong mode: %s(%d), expected: %s(%d)",
				tst_mempolicy_mode_name(mode), mode,
				tst_mempolicy_mode_name(tc->mode), tc->mode);
			fail = 1;
		}
		if (tc->exp_nodemask) {
			struct bitmask *exp_mask = *(tc->exp_nodemask);

			if (!numa_bitmask_equal(exp_mask, getnodemask)) {
				tst_res(TFAIL, "masks are not equal");
				tst_res_hexd(TINFO, exp_mask->maskp,
					exp_mask->size / 8, "exp_mask: ");
				tst_res_hexd(TINFO, getnodemask->maskp,
					getnodemask->size / 8, "returned: ");
				fail = 1;
			}
		}
	}

	if (TST_RET != tc->ret) {
		tst_res(TFAIL, "wrong return code: %ld, expected: %d",
			TST_RET, tc->ret);
		fail = 1;
	}
	if (TST_RET == -1 && TST_ERR != tc->err) {
		tst_res(TFAIL | TTERRNO, "expected errno: %s, got",
			tst_strerrno(tc->err));
		fail = 1;
	}
	if (!fail)
		tst_res(TPASS, "Test passed");
}

static struct tst_test test = {
	.tcnt = ARRAY_SIZE(tcase),
	.test = do_test,
	.setup = setup,
};

#else
	TST_TEST_TCONF(NUMA_ERROR_MSG);
#endif
