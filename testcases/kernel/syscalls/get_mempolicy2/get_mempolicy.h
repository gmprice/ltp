/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (c) 2023 Gregory Price <gregory.price@memverge.com>
 */

#ifndef GET_MEMPOLICY_H__
#define GET_MEMPOLICY_H__

#define SET_MEMPOLICY2 457
#define GET_MEMPOLICY2 458

struct mpol_args {
	uint16_t mode;
	uint16_t mode_flags;
	int32_t home_node;
	uint64_t pol_nodes;
	uint64_t il_weights;
	uint64_t pol_maxnodes;
	int32_t policy_node;
};

static int get_mempolicy2(struct mpol_args *args, uint64_t addr, unsigned int flags)
{
	return syscall(GET_MEMPOLICY2, args, sizeof(*args), addr, flags);
}

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
	args.policy_node = 0;

	return syscall(SET_MEMPOLICY2, &args, sizeof(args), 0);
}


#endif /* GET_MEMPOLICY_H__ */
