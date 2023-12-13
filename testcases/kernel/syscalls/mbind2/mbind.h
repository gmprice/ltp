/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (c) 2019 Cyril Hrubis <chrubis@suse.cz>
 */

#ifndef MBIND_H__
#define MBIND_H__
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

#define MPOL_MF_HOME_NODE (1 << 4)
#define MBIND2 (459)

struct mpol_args {
        uint16_t mode;
        uint16_t mode_flags;
        int32_t home_node;
        uint64_t pol_nodes;
        uint64_t il_weights;
        uint64_t pol_maxnodes;
        int32_t policy_node;
};

static inline const char *mbind_flag_name(unsigned flag)
{
	switch (flag) {
	case 0:
		return "0";
	case MPOL_MF_STRICT:
		return "MPOL_MF_STRICT";
	case MPOL_MF_MOVE:
		return "MPOL_MF_MOVE";
	case MPOL_MF_MOVE_ALL:
		return "MPOL_MF_MOVE_ALL";
	case MPOL_MF_HOME_NODE:
		return "MPOL_MF_HOME_NODE";
	default:
		return "???";
	}
}

static int mbind2(unsigned long addr, unsigned long len,
		  unsigned short mode, unsigned short mode_flags,
		  unsigned long *nmask, unsigned long maxnode,
		  char *weights, int home_node, unsigned long flags)
{
	struct mpol_args args;

	args.mode = mode;
	args.mode_flags = mode_flags;
	args.home_node = home_node;
	args.pol_nodes = (uint64_t)nmask;
	args.il_weights = (uint64_t)weights;
	args.pol_maxnodes = maxnode;
	args.policy_node = 0;

	return syscall(MBIND2, addr, len, &args, sizeof(args), flags);
}

#endif /* MBIND_H__ */
