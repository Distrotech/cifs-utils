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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <sys/types.h>

#include "cifsidmap.h"
#include "idmap_plugin.h"

const char *plugin_errmsg;
static void *plugin;

static void *
resolve_symbol(const char *symbol_name)
{
	void *symbol;

	dlerror();
	symbol = dlsym(plugin, symbol_name);
	if (!symbol)
		plugin_errmsg = dlerror();
	return symbol;
}

/*
 * open the plugin. Note that we leave it open over the life of the
 * program. It gets closed on exit.
 */
static int
open_plugin(void)
{
	if (plugin)
		return 0;

	plugin = dlopen(IDMAP_PLUGIN_PATH, RTLD_LAZY);
	if (!plugin) {
		plugin_errmsg = dlerror();
		return -EIO;
	}

	return 0;
}

int
init_plugin(void **handle)
{
	int ret;
	int (*init)(void **, const char **);

	ret = open_plugin();
	if (ret)
		return ret;

	init = resolve_symbol("cifs_idmap_init_plugin");
	if (!init) {
		plugin_errmsg = "cifs_idmap_init_plugin not implemented";
		return -ENOSYS;
	}
	return (*init)(handle, &plugin_errmsg);
}

void
exit_plugin(void *handle)
{
	int (*exit)(void *);

	exit = resolve_symbol("cifs_idmap_exit_plugin");
	if (exit)
		(*exit)(handle);
}

int
sid_to_str(void *handle, const struct cifs_sid *sid, char **name)
{
	int (*entry)(void *, const struct cifs_sid *, char **);

	*(void **)(&entry) = resolve_symbol("cifs_idmap_sid_to_str");
	if (!entry) {
		plugin_errmsg = "cifs_idmap_sid_to_str not implemented";
		return -ENOSYS;
	}

	return (*entry)(handle, sid, name);
}

int
str_to_sid(void *handle, const char *name, struct cifs_sid *sid)
{
	int (*entry)(void *, const char *, struct cifs_sid *);

	*(void **)(&entry) = resolve_symbol("cifs_idmap_str_to_sid");
	if (!entry) {
		plugin_errmsg = "cifs_idmap_str_to_sid not implemented";
		return -ENOSYS;
	}

	return (*entry)(handle, name, sid);
}

int
sids_to_ids(void *handle, const struct cifs_sid *sid, const size_t num,
	  struct cifs_uxid *cuxid)
{
	int (*entry)(void *handle, const struct cifs_sid *sids,
			const size_t num, struct cifs_uxid *cuxid);

	*(void **)(&entry) = resolve_symbol("cifs_idmap_sids_to_ids");
	if (!entry) {
		plugin_errmsg = "cifs_idmap_sids_to_ids not implemented";
		return -ENOSYS;
	}

	return (*entry)(handle, sid, num, cuxid);
}

int
ids_to_sids(void *handle, const struct cifs_uxid *cuxid, const size_t num,
		struct cifs_sid *sid)
{
	int (*entry)(void *handle, const struct cifs_uxid *cuxid,
			const size_t num, struct cifs_sid *sid);

	*(void **)(&entry) = resolve_symbol("cifs_idmap_ids_to_sids");
	if (!entry) {
		plugin_errmsg = "cifs_idmap_ids_to_sids not implemented";
		return -ENOSYS;
	}

	return (*entry)(handle, cuxid, num, sid);
}
