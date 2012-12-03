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

/* Plugins should implement the following functions: */

/**
 * cifs_idmap_init_plugin - Initialize the plugin interface
 * @handle - return pointer for an opaque handle
 * @errmsg - pointer to error message pointer
 *
 * This function should do whatever is required to establish a context
 * for later ID mapping operations. The "handle" is an opaque context
 * cookie that will be passed in on subsequent ID mapping operations.
 * The errmsg is used to pass back an error string both during the init
 * and in subsequent idmapping functions. On any error, the plugin
 * should point *errmsg at a string describing that error. Returns 0
 * on success and non-zero on error.
 *
 * int cifs_idmap_init_plugin(void **handle, const char **errmsg);
 */

/**
 * cifs_idmap_exit_plugin - Destroy an idmapping context
 * @handle - context handle that should be destroyed
 *
 * When programs are finished with the idmapping plugin, they'll call
 * this function to destroy any context that was created during the
 * init_plugin. The handle passed back in was the one given by the init
 * routine.
 *
 * void cifs_idmap_exit_plugin(void *handle);
 */

/**
 * cifs_idmap_sid_to_str - convert cifs_sid to a string
 * @handle - context handle
 * @sid    - pointer to a cifs_sid
 * @name   - return pointer for the name
 *
 * This function should convert the given cifs_sid to a string
 * representation in a heap-allocated buffer. The caller of this
 * function is expected to free "name" on success. Returns 0 on
 * success and non-zero on error.
 *
 * int cifs_idmap_sid_to_str(void *handle, const struct cifs_sid *sid,
 * 				char **name);
 */

#endif /* _CIFSIDMAP_H */
