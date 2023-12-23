/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (c) 2018 Cyril Hrubis <chrubis@suse.cz>
 * Copyright (c) 2023 Gregory Price <gregory.price@memverge.com>
 */

#ifndef SET_MEMPOLICY_H__
#define SET_MEMPOLICY_H__

static inline void alloc_fault_count(struct tst_nodemap *nodes,
                                     const char *file, size_t size)
{
	void *ptr;

	ptr = tst_numa_map(file, size);
	tst_numa_fault(ptr, size);
	tst_nodemap_count_pages(nodes, ptr, size);
	tst_numa_unmap(ptr, size);
}

#define SET_MEMPOLICY2 457

struct mpol_args {
	uint16_t mode;
	uint16_t mode_flags;
	int32_t home_node;
	uint64_t pol_maxnodes;
	uint64_t pol_nodes;
	uint64_t il_weights;
};

static int set_mempolicy2(uint16_t mode, uint16_t mode_flags, unsigned long *bm,
			  unsigned long maxnode, void *weights)
{
	struct mpol_args args;

	args.mode = mode;
	args.mode_flags = mode_flags;
	args.home_node = -1;
	args.pol_nodes = (uint64_t)bm;
	args.il_weights = (uint64_t)weights;
	args.pol_maxnodes = maxnode;

	return syscall(SET_MEMPOLICY2, &args, sizeof(args), 0);
}


#endif /* SET_MEMPOLICY_H__ */
