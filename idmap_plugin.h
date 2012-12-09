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

#include "cifsidmap.h"

#ifndef _IDMAP_PLUGIN_H
#define _IDMAP_PLUGIN_H

/*
 * On error, plugin functions will set this pointer to a string description
 * of the error. The string should not be freed.
 */
extern const char *plugin_errmsg;

/*
 * External API. Programs should call this to use the plugin functionality.
 */

/*
 * Initialize plugin. Returns an opaque handle that should be passed to
 * other idmapping functions.
 */
extern int init_plugin(void **handle);

/* Close out an init'ed handle */
extern void exit_plugin(void *handle);

/* Convert cifs_sid to a string. Caller must free *name on success */
extern int sid_to_str(void *handle, const struct cifs_sid *sid, char **name);

/* Convert string to cifs_sid. */
extern int str_to_sid(void *handle, const char *name, struct cifs_sid *csid);

/* convert array of cifs_sids to cifs_uxids */
extern int sids_to_ids(void *handle, const struct cifs_sid *sids,
			const size_t num, struct cifs_uxid *ids);

/* convert array of cifs_uxids to cifs_sids */
extern int ids_to_sids(void *handle, const struct cifs_uxid *id,
			const size_t num, struct cifs_sid *sid);

#endif /* _IDMAP_PLUGIN_H */
