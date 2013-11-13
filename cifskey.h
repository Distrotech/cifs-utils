/*
 * Credentials stashing utility for Linux CIFS VFS (virtual filesystem) definitions
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

#ifndef _CIFSKEY_H
#define _CIFSKEY_H

#define KEY_PREFIX	  "cifs"

/* max length of username, password and domain name */
#define MAX_USERNAME_SIZE 32
#define MOUNT_PASSWD_SIZE 128
#define MAX_DOMAIN_SIZE 64

/*
 * disallowed characters for user and domain names. See:
 * http://technet.microsoft.com/en-us/library/bb726984.aspx
 * http://support.microsoft.com/kb/909264
 */
#define USER_DISALLOWED_CHARS "\\/\"[]:|<>+=;,?*"
#define DOMAIN_DISALLOWED_CHARS "\\/:*?\"<>|"

/* destination keyring */
#define DEST_KEYRING KEY_SPEC_SESSION_KEYRING
#define CIFS_KEY_TYPE  "logon"
#define CIFS_KEY_PERMS (KEY_POS_VIEW|KEY_POS_WRITE|KEY_POS_SEARCH| \
			KEY_USR_VIEW|KEY_USR_WRITE|KEY_USR_SEARCH)

key_serial_t key_search(const char *addr, char keytype);
key_serial_t key_add(const char *addr, const char *user, const char *pass, char keytype);

#endif /* _CIFSKEY_H */
