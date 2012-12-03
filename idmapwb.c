/*
 * Winbind ID Mapping Plugin
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

#include <stdint.h>
#include <endian.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <wbclient.h>

#include "cifsidmap.h"

static const char **plugin_errmsg;

/*
 * Winbind keeps wbcDomainSid fields in host-endian. Copy fields from the
 * csid to the wsid, while converting the subauthority fields from LE.
 */
static void
csid_to_wsid(struct wbcDomainSid *wsid, const struct cifs_sid *csid)
{
	int i;
	uint8_t num_subauth = (csid->num_subauth <= WBC_MAXSUBAUTHS) ?
				csid->num_subauth : WBC_MAXSUBAUTHS;

	wsid->sid_rev_num = csid->revision;
	wsid->num_auths = num_subauth;
	for (i = 0; i < NUM_AUTHS; i++)
		wsid->id_auth[i] = csid->authority[i];
	for (i = 0; i < num_subauth; i++)
		wsid->sub_auths[i] = le32toh(csid->sub_auth[i]);
}

int
cifs_idmap_sid_to_str(void *handle __attribute__ ((unused)),
			const struct cifs_sid *csid, char **string)
{
	int rc;
	wbcErr wbcrc;
	char *domain = NULL;
	char *name = NULL;
	enum wbcSidType sntype;
	struct wbcDomainSid wsid;
	size_t len;

	csid_to_wsid(&wsid, csid);

	wbcrc = wbcLookupSid(&wsid, &domain, &name, &sntype);
	if (!WBC_ERROR_IS_OK(wbcrc)) {
		*plugin_errmsg = wbcErrorString(wbcrc);
		return -EIO;
	}

	/* +1 for '\\' and +1 for NULL terminator */
	len = strlen(domain) + 1 + strlen(name) + 1;

	*string = malloc(len);
	if (!*string) {
		*plugin_errmsg = "Unable to allocate memory";
		rc = -ENOMEM;
		goto out;
	}

	rc = snprintf(*string, len, "%s\\%s", domain, name);
	if (rc >= (long)len) {
		free(*string);
		*plugin_errmsg = "Resulting string was truncated";
		*string = NULL;
		rc = -EIO;
	} else {
		rc = 0;
	}
out:
	wbcFreeMemory(domain);
	wbcFreeMemory(name);
	return rc;
}

/*
 * For the winbind plugin, we don't need to do anything special on
 * init or exit
 */
int
cifs_idmap_init_plugin(void **handle __attribute__((unused)), const char **errmsg)
{
	plugin_errmsg = errmsg;
	return 0;
}

void
cifs_idmap_exit_plugin(void *handle __attribute__((unused)))
{
	return;
}
