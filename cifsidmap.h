/*
 * ID Mapping Plugin interface for cifs-utils
 * Copyright (C) 2012 Jeff Layton (jlayton@samba.org)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdint.h>

#ifndef _CIFSIDMAP_H
#define _CIFSIDMAP_H

#define NUM_AUTHS (6)			/* number of authority fields */
#define SID_MAX_SUB_AUTHORITIES (15)	/* max number of sub authority fields */

/*
 * Binary representation of a SID as presented to/from the kernel. Note that
 * the sub_auth field is always stored in little-endian here.
 */
struct cifs_sid {
	uint8_t revision; /* revision level */
	uint8_t num_subauth;
	uint8_t authority[NUM_AUTHS];
	uint32_t sub_auth[SID_MAX_SUB_AUTHORITIES];
} __attribute__((packed));

#endif /* _CIFSIDMAP_H */
