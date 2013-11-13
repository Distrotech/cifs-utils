/*
 * Credentials stashing routines for Linux CIFS VFS (virtual filesystem)
 * Copyright (C) 2010 Jeff Layton (jlayton@samba.org)
 * Copyright (C) 2010 Igor Druzhinin (jaxbrigs@gmail.com)
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

#include <sys/types.h>
#include <keyutils.h>
#include <stdio.h>
#include "cifskey.h"
#include "resolve_host.h"

/* search a specific key in keyring */
key_serial_t
key_search(const char *addr, char keytype)
{
	char desc[INET6_ADDRSTRLEN + sizeof(KEY_PREFIX) + 4];

	sprintf(desc, "%s:%c:%s", KEY_PREFIX, keytype, addr);

	return keyctl_search(DEST_KEYRING, CIFS_KEY_TYPE, desc, 0);
}

/* add or update a specific key to keyring */
key_serial_t
key_add(const char *addr, const char *user, const char *pass, char keytype)
{
	int len;
	char desc[INET6_ADDRSTRLEN + sizeof(KEY_PREFIX) + 4];
	char val[MOUNT_PASSWD_SIZE +  MAX_USERNAME_SIZE + 2];

	/* set key description */
	sprintf(desc, "%s:%c:%s", KEY_PREFIX, keytype, addr);

	/* set payload contents */
	len = sprintf(val, "%s:%s", user, pass);

	return add_key(CIFS_KEY_TYPE, desc, val, len + 1, DEST_KEYRING);
}
