/*
* CIFS idmap helper.
* Copyright (C) Shirish Pargaonkar (shirishp@us.ibm.com) 2011
*
* Used by /sbin/request-key.conf for handling
* cifs upcall for SID to uig/gid and uid/gid to SID mapping.
* You should have keyutils installed and add
* this lines to /etc/request-key.conf file:

    create cifs.idmap * * /usr/local/sbin/cifs.idmap %k

* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <string.h>
#include <getopt.h>
#include <syslog.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <keyutils.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>

#include "cifsacl.h"
#include "idmap_plugin.h"

static void *plugin_handle;

static const char *prog = "cifs.idmap";

static const struct option long_options[] = {
	{"help", 0, NULL, 'h'},
	{"timeout", 1, NULL, 't'},
	{"version", 0, NULL, 'v'},
	{NULL, 0, NULL, 0}
};

static void usage(void)
{
	fprintf(stderr, "Usage: %s [-h] [-v] [-t timeout] key_serial\n", prog);
}

static char *
strget(const char *str, const char *substr)
{
	int sublen;
	char *substrptr;

	/* find the prefix */
	substrptr = strstr(str, substr);
	if (!substrptr)
		return substrptr;

	/* skip over it */
	sublen = strlen(substr);
	substrptr += sublen;

	/* if there's nothing after the prefix, return NULL */
	if (*substrptr == '\0')
		return NULL;

	return substrptr;
}

/*
 * Convert a string representation of unsigned int into a numeric one. Also
 * check for incomplete string conversion and overflow.
 */
static int
str_to_uint(const char *src, unsigned int *dst)
{
	unsigned long tmp;
	char *end;

	errno = 0;
	tmp = strtoul(src, &end, 0);

	if (*end != '\0')
		return EINVAL;
	if (tmp > UINT_MAX)
		return EOVERFLOW;

	*dst = (unsigned int)tmp;
	return 0;
}

static int
cifs_idmap(const key_serial_t key, const char *key_descr)
{
	int rc = 1;
	char *sidstr = NULL;
	struct cifs_sid sid;
	struct cifs_uxid cuxid;

	/*
	 * Use winbind to convert received string to a SID and lookup
	 * name and map that SID to an uid.  If either of these
	 * function calls return with an error, return an error the
	 * upcall caller.  Otherwise instanticate a key using that uid.
	 *
	 * The same applies to SID and gid mapping.
	 */
	sidstr = strget(key_descr, "os:");
	if (sidstr) {
		rc = str_to_sid(plugin_handle, sidstr, &sid);
		if (rc) {
			syslog(LOG_DEBUG, "Unable to convert owner string %s "
				"to SID: %s", key_descr, plugin_errmsg);
			goto cifs_idmap_ret;
		}

		rc = sids_to_ids(plugin_handle, &sid, 1, &cuxid);
		if (rc || (cuxid.type != CIFS_UXID_TYPE_UID &&
			   cuxid.type != CIFS_UXID_TYPE_BOTH)) {
			syslog(LOG_DEBUG, "Unable to convert %s to "
				"UID: %s", key_descr, plugin_errmsg);
			rc = rc ? rc : -EINVAL;
			goto cifs_idmap_ret;
		}
		rc = keyctl_instantiate(key, &cuxid.id.uid, sizeof(uid_t), 0);
		if (rc)
			syslog(LOG_ERR, "%s: key inst: %s", __func__,
					strerror(errno));

		goto cifs_idmap_ret;
	}

	sidstr = strget(key_descr, "gs:");
	if (sidstr) {
		rc = str_to_sid(plugin_handle, sidstr, &sid);
		if (rc) {
			syslog(LOG_DEBUG, "Unable to convert group string %s "
				"to SID: %s", key_descr, plugin_errmsg);
			goto cifs_idmap_ret;
		}

		rc = sids_to_ids(plugin_handle, &sid, 1, &cuxid);
		if (rc || (cuxid.type != CIFS_UXID_TYPE_GID &&
			   cuxid.type != CIFS_UXID_TYPE_BOTH)) {
			syslog(LOG_DEBUG, "Unable to convert %s to "
				"GID: %s", key_descr, plugin_errmsg);
			rc = rc ? rc : -EINVAL;
			goto cifs_idmap_ret;
		}
		rc = keyctl_instantiate(key, &cuxid.id.gid, sizeof(gid_t), 0);
		if (rc)
			syslog(LOG_ERR, "%s: key inst: %s", __func__,
					strerror(errno));

		goto cifs_idmap_ret;
	}

	sidstr = strget(key_descr, "oi:");
	if (sidstr) {
		rc = str_to_uint(sidstr, (unsigned int *)&cuxid.id.uid);
		if (rc) {
			syslog(LOG_ERR, "Unable to convert %s to uid: %s",
				sidstr, strerror(rc));
			goto cifs_idmap_ret;
		}
		cuxid.type = CIFS_UXID_TYPE_UID;

		syslog(LOG_DEBUG, "SID: %s, uid: %u", sidstr, cuxid.id.uid);
		rc = ids_to_sids(plugin_handle, &cuxid, 1, &sid);
		if (rc || sid.revision == 0) {
			syslog(LOG_DEBUG, "uid %u to SID error: %s",
				cuxid.id.uid, plugin_errmsg);
			goto cifs_idmap_ret;
		}

		rc = keyctl_instantiate(key, &sid, sizeof(struct cifs_sid), 0);
		if (rc)
			syslog(LOG_ERR, "%s: key inst: %s", __func__,
				strerror(errno));

		goto cifs_idmap_ret;
	}

	sidstr = strget(key_descr, "gi:");
	if (sidstr) {
		rc = str_to_uint(sidstr, (unsigned int *)&cuxid.id.gid);
		if (rc) {
			syslog(LOG_ERR, "Unable to convert %s to gid: %s",
				sidstr, strerror(rc));
			goto cifs_idmap_ret;
		}
		cuxid.type = CIFS_UXID_TYPE_GID;

		syslog(LOG_DEBUG, "SID: %s, gid: %u", sidstr, cuxid.id.gid);
		rc = ids_to_sids(plugin_handle, &cuxid, 1, &sid);
		if (rc || sid.revision == 0) {
			syslog(LOG_DEBUG, "gid %u to SID error: %s",
				cuxid.id.gid, plugin_errmsg);
			goto cifs_idmap_ret;
		}

		rc = keyctl_instantiate(key, &sid, sizeof(struct cifs_sid), 0);
		if (rc)
			syslog(LOG_ERR, "%s: key inst: %s", __func__,
				strerror(errno));

		goto cifs_idmap_ret;
	}

	syslog(LOG_DEBUG, "Invalid key: %s", key_descr);

cifs_idmap_ret:
	return rc;
}

int main(const int argc, char *const argv[])
{
	int c;
	long rc;
	key_serial_t key = 0;
	char *buf;
	unsigned int timeout = 600; /* default idmap cache timeout */

	openlog(prog, 0, LOG_DAEMON);

	while ((c = getopt_long(argc, argv, "ht:v",
					long_options, NULL)) != -1) {
		switch (c) {
		case 'h':
			rc = 0;
			usage();
			goto out;
		case 't':
			rc = str_to_uint(optarg, &timeout);
			if (rc) {
				syslog(LOG_ERR, "bad timeout value %s: %s",
					optarg, strerror(rc));
				goto out;
			}
			break;
		case 'v':
			rc = 0;
			printf("version: %s\n", VERSION);
			goto out;
		default:
			rc = EINVAL;
			syslog(LOG_ERR, "unknown option: %c", c);
			goto out;
		}
	}

	rc = 1;
	/* is there a key? */
	if (argc <= optind) {
		usage();
		goto out;
	}

	/* get key and keyring values */
	errno = 0;
	key = strtol(argv[optind], NULL, 10);
	if (errno != 0) {
		key = 0;
		syslog(LOG_ERR, "Invalid key format: %s", strerror(errno));
		goto out;
	}

	if (init_plugin(&plugin_handle)) {
		plugin_handle = NULL;
		syslog(LOG_ERR, "Unable to initialize ID mapping plugin: %s",
			plugin_errmsg);
		goto out;
	}

	/* set timeout on key */
	rc = keyctl_set_timeout(key, timeout);
	if (rc == -1) {
		syslog(LOG_ERR, "unable to set key timeout: %s",
			strerror(errno));
		goto out_exit_plugin;
	}

	rc = keyctl_describe_alloc(key, &buf);
	if (rc == -1) {
		syslog(LOG_ERR, "keyctl_describe_alloc failed: %s",
		       strerror(errno));
		goto out_exit_plugin;
	}

	syslog(LOG_DEBUG, "key description: %s", buf);

	rc = cifs_idmap(key, buf);
out_exit_plugin:
	exit_plugin(plugin_handle);
out:
	return rc;
}
