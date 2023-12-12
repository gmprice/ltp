// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2018 Cyril Hrubis <chrubis@suse.cz>
 */

/*
 * We are testing set_mempolicy2() with MPOL_WEIGHTED_INTERLEAVE.
 *
 * The test tries different subsets of memory nodes, sets the mask with
 * memopolicy, and checks that the memory was interleaved between the nodes
 * accordingly.
 */

#define _GNU_SOURCE
#include <sched.h>
#include <errno.h>
#include "config.h"
#ifdef HAVE_NUMA_V2
# include <numa.h>
# include <numaif.h>
#endif
#include "tst_test.h"
#include "tst_numa.h"

#ifdef HAVE_NUMA_V2

#include "set_mempolicy.h"

#define MPOL_WEIGHTED_INTERLEAVE 6

#define ALLOC_ON_NODE 8

static size_t page_size;
static struct tst_nodemap *nodes;

static void setup(void)
{
	page_size = getpagesize();

	nodes = tst_get_nodemap(TST_NUMA_MEM, 2 * ALLOC_ON_NODE * page_size / 1024);
	if (nodes->cnt <= 1)
		tst_brk(TCONF, "Test requires at least two NUMA memory nodes");
}

static void cleanup(void)
{
	tst_nodemap_free(nodes);
}

static int shifted_check(unsigned int start, unsigned char *weights,
			 unsigned int rounds, unsigned int delta)
{
	unsigned int exp, i;
	for (i = start; i < nodes->cnt; i++) {
		exp = rounds * weights[i];
		if (delta < weights[i]) {
			exp += delta;
			delta = 0;
		} else {
			exp += weights[i];
			delta -= weights[i];
		}
		if (nodes->counters[i] == exp)
			continue;
		else
			return -1;
	}
	for (i = 0; i < start; i++) {
		exp = rounds * weights[i];
		if (delta < weights[i]) {
			exp += delta;
			delta = 0;
		} else {
			exp += weights[i];
			delta -= weights[i];
		}
		if (nodes->counters[i] == exp)
			continue;
		else
			return -1;
	}
	return 0;
}

static void alloc_and_check(unsigned int size, unsigned char *weights,
			    unsigned int rounds, unsigned int delta)
{
	unsigned int i, err;
	const char *prefix = "child: ";

	if (SAFE_FORK()) {
		prefix = "parent: ";
		tst_reap_children();
	}

	tst_nodemap_reset_counters(nodes);
	alloc_fault_count(nodes, NULL, size * page_size);

	/*
	 * It is unknown which node we started allocations from,
	 * we need to check as if we started from each node
	 */
	for (i = 0; i < nodes->cnt; i++) {
		err = shifted_check(i, weights, rounds, delta);
		if (!err)
			break;
	}
	if (err)
		tst_res(TFAIL, "%sUnexpected allocation distribution - size %d",
				prefix, size);
	else
		tst_res(TPASS, "%sCorrect allocation distribution - size %d",
				prefix, size);
	
}

static void verify_set_mempolicy2(unsigned int n)
{
	struct bitmask *bm = numa_allocate_nodemask();
	unsigned int alloc_on_nodes = n ? 2 : nodes->cnt;
	unsigned int alloc_total = nodes->cnt * (n ? 8 : 2);
	unsigned char weight;
	unsigned int weight_total = 0;
	unsigned char weights[bm->size+1];
	unsigned int i = 0, rounds = 0, delta = 0;

	memset(weights, 0, sizeof(weights));

	/* set weights to N+1 */
	for (i = 0; i < nodes->cnt; i++) {
		weight = i+1;
		weights[i] = weight;
		weight_total += weight;
	}
	rounds = alloc_total / weight_total;
	delta = alloc_total % weight_total;

	for (i = 0; i < nodes->cnt; i++)
		numa_bitmask_setbit(bm, nodes->map[i]);

	TEST(set_mempolicy2(MPOL_WEIGHTED_INTERLEAVE, 0, bm->maskp, bm->size+1, &weights));

	tst_res(TINFO, "Allocating on nodes 1-%u - %u pages",
	        alloc_on_nodes, alloc_total);

	if (TST_RET) {
		tst_res(TFAIL | TTERRNO,
		        "set_mempolicy2(MPOL_WEIGHTED_INTERLEAVE)");
		return;
	}

	tst_res(TPASS, "set_mempolicy2(MPOL_WEIGHTED_INTERLEAVE)");

	numa_free_nodemask(bm);

	alloc_and_check(alloc_total, weights, rounds, delta);
}

static struct tst_test test = {
	.setup = setup,
	.cleanup = cleanup,
	.test = verify_set_mempolicy2,
	.tcnt = 2,
	.forks_child = 1,
	.needs_checkpoints = 1,
};

#else

TST_TEST_TCONF(NUMA_ERROR_MSG);

#endif /* HAVE_NUMA_V2 */
