/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (c) 2023 Gregory Price <gregory.price@memverge.com>
 */

#ifndef GET_MEMPOLICY_H__
#define GET_MEMPOLICY_H__

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

static int get_mempolicy2(struct mpol_args *args, uint64_t addr, int *addr_node, unsigned int flags)
{
	return syscall(GET_MEMPOLICY2, args, sizeof(*args), addr, addr_node, flags);
}


#endif /* GET_MEMPOLICY_H__ */
