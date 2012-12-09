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
#include <limits.h>

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

/*
 * Winbind keeps wbcDomainSid fields in host-endian. Copy fields from the
 * wsid to the csid, while converting the subauthority fields to LE.
 */
static void
wsid_to_csid(struct cifs_sid *csid, struct wbcDomainSid *wsid)
{
	int i;
	uint8_t num_subauth = (wsid->num_auths <= SID_MAX_SUB_AUTHORITIES) ?
				wsid->num_auths : SID_MAX_SUB_AUTHORITIES;

	csid->revision = wsid->sid_rev_num;
	csid->num_subauth = num_subauth;
	for (i = 0; i < NUM_AUTHS; i++)
		csid->authority[i] = wsid->id_auth[i];
	for (i = 0; i < num_subauth; i++)
		csid->sub_auth[i] = htole32(wsid->sub_auths[i]);
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

int
cifs_idmap_str_to_sid(void *handle __attribute__ ((unused)),
			const char *orig, struct cifs_sid *csid)
{
	wbcErr wbcrc;
	char *name, *domain, *sidstr;
	enum wbcSidType type;
	struct wbcDomainSid wsid;

	sidstr = strdup(orig);
	if (!sidstr) {
		*plugin_errmsg = "Unable to copy string";
		return -ENOMEM;
	}

	name = strchr(sidstr, '\\');
	if (!name) {
		/* might be a raw string representation of SID */
		wbcrc = wbcStringToSid(sidstr, &wsid);
		if (WBC_ERROR_IS_OK(wbcrc))
			goto convert_sid;

		domain = "";
		name = sidstr;
	} else {
		domain = sidstr;
		*name = '\0';
		++name;
	}

	wbcrc = wbcLookupName(domain, name, &wsid, &type);
	/* FIXME: map these to better POSIX error codes? */
	if (!WBC_ERROR_IS_OK(wbcrc)) {
		*plugin_errmsg = wbcErrorString(wbcrc);
		free(sidstr);
		return -EIO;
	}

convert_sid:
	wsid_to_csid(csid, &wsid);
	free(sidstr);
	return 0;
}

static void
wuxid_to_cuxid(struct cifs_uxid *cuxid, const struct wbcUnixId *wuxid)
{
	switch(wuxid->type) {
	case WBC_ID_TYPE_UID:
		cuxid->id.uid = wuxid->id.uid;
		cuxid->type = CIFS_UXID_TYPE_UID;
		break;
	case WBC_ID_TYPE_GID:
		cuxid->id.gid = wuxid->id.gid;
		cuxid->type = CIFS_UXID_TYPE_GID;
		break;
#ifdef HAVE_WBC_ID_TYPE_BOTH
	case WBC_ID_TYPE_BOTH:
		cuxid->id.uid = wuxid->id.uid;
		cuxid->type = CIFS_UXID_TYPE_BOTH;
		break;
#endif /* HAVE_WBC_ID_TYPE_BOTH */
	default:
		cuxid->type = CIFS_UXID_TYPE_UNKNOWN;
	}
}

int
cifs_idmap_sids_to_ids(void *handle __attribute__((unused)),
			const struct cifs_sid *csid, size_t num,
			struct cifs_uxid *cuxid)
{
	int ret;
	unsigned int i;
	wbcErr wbcret;
	struct wbcDomainSid *wsid;
	struct wbcUnixId *wuxid;

	if (num > UINT_MAX) {
		*plugin_errmsg = "num is too large.";
		return -EINVAL;
	}

	wsid = calloc(num, sizeof(*wsid));
	if (!wsid) {
		*plugin_errmsg = "Unable to allocate memory.";
		return -ENOMEM;
	}

	wuxid = calloc(num, sizeof(*wuxid));
	if (!wuxid) {
		*plugin_errmsg = "Unable to allocate memory.";
		ret = -ENOMEM;
		goto out;
	}

	for (i = 0; i < num; ++i)
		csid_to_wsid(&wsid[i], &csid[i]);

	/*
	 * Winbind does not set an error message in the event that some
	 * mappings fail. So, we preemptively do it here, just in case.
	 */
	*plugin_errmsg = "Some IDs could not be mapped.";

	wbcret = wbcSidsToUnixIds(wsid, num, wuxid);
	if (!WBC_ERROR_IS_OK(wbcret)) {
		*plugin_errmsg = wbcErrorString(wbcret);
		ret = -EIO;
		goto out;
	}

	ret = 0;
	for (i = 0; i < num; ++i)
		wuxid_to_cuxid(&cuxid[i], &wuxid[i]);
out:
	free(wuxid);
	free(wsid);
	return ret;
}

int
cifs_idmap_ids_to_sids(void *handle __attribute__((unused)),
			const struct cifs_uxid *cuxid, size_t num,
			struct cifs_sid *csid)
{
	int ret = -EIO;
	wbcErr wbcrc;
	size_t i;
	struct wbcDomainSid wsid;

	for (i = 0; i < num; ++i) {
		switch(cuxid[i].type) {
		case CIFS_UXID_TYPE_UID:
			wbcrc = wbcUidToSid(cuxid[i].id.uid, &wsid);
			break;
		case CIFS_UXID_TYPE_GID:
			wbcrc = wbcGidToSid(cuxid[i].id.gid, &wsid);
			break;
		case CIFS_UXID_TYPE_BOTH:
			/*
			 * In the BOTH case, prefer a user type first and fall
			 * back to a group if that doesn't map.
			 */
			wbcrc = wbcUidToSid(cuxid[i].id.uid, &wsid);
			if (WBC_ERROR_IS_OK(wbcrc))
				break;
			wbcrc = wbcGidToSid(cuxid[i].id.gid, &wsid);
			break;
		default:
			csid[i].revision = 0;
			*plugin_errmsg = "Invalid CIFS_UXID_TYPE value";
			continue;
		}

		if (WBC_ERROR_IS_OK(wbcrc)) {
			ret = 0;
			wsid_to_csid(&csid[i], &wsid);
		} else {
			csid[i].revision = 0;
			*plugin_errmsg = wbcErrorString(wbcrc);
		}
	}
	return ret;
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
