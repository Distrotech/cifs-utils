/*
 * Copyright (C) 2013 Orion Poplawski <orion@cora.nwra.com>
 *
 * based on gkr-pam-module.c, Copyright (C) 2007 Stef Walter
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
 * along with this program; if not, write to the Free Software
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
/*
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
*/

#include <keyutils.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include "cifskey.h"
#include "mount.h"
#include "resolve_host.h"
#include "util.h"

/**
 * Flags that can be passed to the PAM module
 */
enum {
	ARG_DOMAIN	   = 1 << 0,	/** Set domain password */
	ARG_DEBUG	   = 1 << 1	/** Print debug messages */
};

/**
 * Parse the arguments passed to the PAM module.
 *
 * @param ph PAM handle
 * @param argc number of arguments
 * @param argv array of arguments
 * @param kwalletopener kwalletopener argument, path to the kwalletopener binary
 * @return ORed flags that have been parsed
 */
static uint parse_args (pam_handle_t *ph, int argc, const char **argv, const char **hostdomain)
{
	uint args = 0;
	const void *svc;
	int i;
	const char *host = NULL;
	const char *domain = NULL;

	svc = NULL;
	if (pam_get_item (ph, PAM_SERVICE, &svc) != PAM_SUCCESS) {
		svc = NULL;
	}

	size_t host_len = strlen("host=");
	size_t domain_len = strlen("domain=");

	/* Parse the arguments */
	for (i = 0; i < argc; i++) {
		if (strncmp(argv[i], "host=", host_len) == 0) {
			host = (argv[i]) + host_len;
			if (*host == '\0') {
				host = NULL;
				pam_syslog(ph, LOG_ERR, ""
					   "host= specification missing argument");
			} else {
				*hostdomain = host;
			}
		} else if (strncmp(argv[i], "domain=", domain_len) == 0) {
			domain = (argv[i]) + domain_len;
			if (*domain == '\0') {
				domain = NULL;
				pam_syslog(ph, LOG_ERR, ""
					   "domain= specification missing argument");
			} else {
				*hostdomain = domain;
				args |= ARG_DOMAIN;
			}
		} else if (strcmp(argv[i], "debug") == 0) {
			args |= ARG_DEBUG;
		} else {
			pam_syslog(ph, LOG_ERR, "invalid option %s",
				   argv[i]);
		}
	}

	if (host && domain) {
		pam_syslog(ph, LOG_ERR, "cannot specify both host= and "
			   "domain= arguments");
	}

	return args;
}

static void
free_password (char *password)
{
	volatile char *vp;
	size_t len;

	if (!password) {
		return;
	}

	/* Defeats some optimizations */
	len = strlen (password);
	memset (password, 0xAA, len);
	memset (password, 0xBB, len);

	/* Defeats others */
	vp = (volatile char*)password;
	while (*vp) {
		*(vp++) = 0xAA;
	}

	free (password);
}

static void
cleanup_free_password (pam_handle_t *ph __attribute__((unused)), void *data,
			int pam_end_status __attribute__((unused)))
{
	free_password (data);
}

/**
 * Set the cifs credentials
 *
 * @param ph PAM handle
 * @param user
 * @param password
 * @param args ORed flags for this module
 * @param hostdomain hostname or domainname
 */
static int cifscreds_pam_add(pam_handle_t *ph, const char *user, const char *password,
			     uint args, const char *hostdomain)
{
	int ret = PAM_SUCCESS;
	char addrstr[MAX_ADDR_LIST_LEN];
	char *currentaddress, *nextaddress;
	char keytype = ((args & ARG_DOMAIN) == ARG_DOMAIN) ? 'd' : 'a';

	assert(user);
	assert(password);
	assert(hostdomain);

	if (keytype == 'd') {
		if (strpbrk(hostdomain, DOMAIN_DISALLOWED_CHARS)) {
			pam_syslog(ph, LOG_ERR, "Domain name contains invalid characters");
			return PAM_SERVICE_ERR;
		}
		strlcpy(addrstr, hostdomain, MAX_ADDR_LIST_LEN);
	} else {
		ret = resolve_host(hostdomain, addrstr);
	}

	switch (ret) {
	case EX_USAGE:
		pam_syslog(ph, LOG_ERR, "Could not resolve address for %s", hostdomain);
		return PAM_SERVICE_ERR;

	case EX_SYSERR:
		pam_syslog(ph, LOG_ERR, "Problem parsing address list");
		return PAM_SERVICE_ERR;
	}

	if (strpbrk(user, USER_DISALLOWED_CHARS)) {
		pam_syslog(ph, LOG_ERR, "Incorrect username");
		return PAM_SERVICE_ERR;
	}

	/* search for same credentials stashed for current host */
	currentaddress = addrstr;
	nextaddress = strchr(currentaddress, ',');
	if (nextaddress)
		*nextaddress++ = '\0';

	while (currentaddress) {
		if (key_search(currentaddress, keytype) > 0) {
			pam_syslog(ph, LOG_WARNING, "You already have stashed credentials "
				"for %s (%s)", currentaddress, hostdomain);

			return PAM_SERVICE_ERR;
		}

		switch(errno) {
		case ENOKEY:
			/* success */
			break;
		default:
			pam_syslog(ph, LOG_ERR, "Unable to search keyring for %s (%s)",
					currentaddress, strerror(errno));
			return PAM_SERVICE_ERR;
		}

		currentaddress = nextaddress;
		if (currentaddress) {
			*(currentaddress - 1) = ',';
			nextaddress = strchr(currentaddress, ',');
			if (nextaddress)
				*nextaddress++ = '\0';
		}
	}

	/* Set the password */
	currentaddress = addrstr;
	nextaddress = strchr(currentaddress, ',');
	if (nextaddress)
		*nextaddress++ = '\0';

	while (currentaddress) {
		key_serial_t key = key_add(currentaddress, user, password, keytype);
		if (key <= 0) {
			pam_syslog(ph, LOG_ERR, "error: Add credential key for %s: %s",
				currentaddress, strerror(errno));
		} else {
			if ((args & ARG_DEBUG) == ARG_DEBUG) {
				pam_syslog(ph, LOG_DEBUG, "credential key for \\\\%s\\%s added",
					   currentaddress, user);
			}
			if (keyctl(KEYCTL_SETPERM, key, CIFS_KEY_PERMS) < 0) {
				pam_syslog(ph, LOG_ERR,"error: Setting permissons "
					"on key, attempt to delete...");

				if (keyctl(KEYCTL_UNLINK, key, DEST_KEYRING) < 0) {
					pam_syslog(ph, LOG_ERR, "error: Deleting key from "
						"keyring for %s (%s)",
						currentaddress, hostdomain);
				}
			}
		}

		currentaddress = nextaddress;
		if (currentaddress) {
			nextaddress = strchr(currentaddress, ',');
			if (nextaddress)
				*nextaddress++ = '\0';
		}
	}

	return PAM_SUCCESS;
}

/**
 * Update the cifs credentials
 *
 * @param ph PAM handle
 * @param user
 * @param password
 * @param args ORed flags for this module
 * @param hostdomain hostname or domainname
 */
static int cifscreds_pam_update(pam_handle_t *ph, const char *user, const char *password,
				uint args, const char *hostdomain)
{
	int ret = PAM_SUCCESS;
	char addrstr[MAX_ADDR_LIST_LEN];
	char *currentaddress, *nextaddress;
	int id, count = 0;
	char keytype = ((args & ARG_DOMAIN) == ARG_DOMAIN) ? 'd' : 'a';

	assert(user);
	assert(password);
	assert(hostdomain);

	if (keytype == 'd') {
		if (strpbrk(hostdomain, DOMAIN_DISALLOWED_CHARS)) {
			pam_syslog(ph, LOG_ERR, "Domain name contains invalid characters");
			return PAM_SERVICE_ERR;
		}
		strlcpy(addrstr, hostdomain, MAX_ADDR_LIST_LEN);
	} else {
		ret = resolve_host(hostdomain, addrstr);
	}

	switch (ret) {
	case EX_USAGE:
		pam_syslog(ph, LOG_ERR, "Could not resolve address for %s", hostdomain);
		return PAM_SERVICE_ERR;

	case EX_SYSERR:
		pam_syslog(ph, LOG_ERR, "Problem parsing address list");
		return PAM_SERVICE_ERR;
	}

	if (strpbrk(user, USER_DISALLOWED_CHARS)) {
		pam_syslog(ph, LOG_ERR, "Incorrect username");
		return PAM_SERVICE_ERR;
	}

	/* search for necessary credentials stashed in session keyring */
	currentaddress = addrstr;
	nextaddress = strchr(currentaddress, ',');
	if (nextaddress)
		*nextaddress++ = '\0';

	while (currentaddress) {
		if (key_search(currentaddress, keytype) > 0)
			count++;

		currentaddress = nextaddress;
		if (currentaddress) {
			nextaddress = strchr(currentaddress, ',');
			if (nextaddress)
				*nextaddress++ = '\0';
		}
	}

	if (!count) {
		pam_syslog(ph, LOG_ERR, "You have no same stashed credentials for %s", hostdomain);
		return PAM_SERVICE_ERR;
	}

	for (id = 0; id < count; id++) {
		key_serial_t key = key_add(currentaddress, user, password, keytype);
		if (key <= 0) {
			pam_syslog(ph, LOG_ERR, "error: Update credential key for %s: %s",
				currentaddress, strerror(errno));
		}
	}

	return PAM_SUCCESS;
}

/**
 * PAM function called during authentication.
 *
 * This function first tries to get a password from PAM. Afterwards two
 * scenarios are possible:
 *
 * - A session is already available which usually means that the user is already
 *	logged on and PAM has been used inside the screensaver. In that case, no need to
 *	do anything(?).
 *
 * - A session is not yet available. Store the password inside PAM data so
 *	it can be retrieved during pam_open_session to set the credentials.
 *
 * @param ph PAM handle
 * @param unused unused
 * @param argc number of arguments for this PAM module
 * @param argv array of arguments for this PAM module
 * @return any of the PAM return values
 */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *ph, int unused __attribute__((unused)), int argc, const char **argv)
{
	const char *hostdomain;
	const char *user;
	const char *password;
	uint args;
	int ret;

	args = parse_args(ph, argc, argv, &hostdomain);

	/* Figure out and/or prompt for the user name */
	ret = pam_get_user(ph, &user, NULL);
	if (ret != PAM_SUCCESS || !user) {
		pam_syslog(ph, LOG_ERR, "couldn't get the user name: %s",
			   pam_strerror(ph, ret));
		return PAM_SERVICE_ERR;
	}

	/* Lookup the password */
	ret = pam_get_item(ph, PAM_AUTHTOK, (const void**)&password);
	if (ret != PAM_SUCCESS || password == NULL) {
		if (ret == PAM_SUCCESS) {
			pam_syslog(ph, LOG_WARNING, "no password is available for user");
		} else {
			pam_syslog(ph, LOG_WARNING, "no password is available for user: %s",
				   pam_strerror(ph, ret));
		}
		return PAM_SUCCESS;
	}

	/* set password as pam data and launch during open_session. */
	if (pam_set_data(ph, "cifscreds_password", strdup(password), cleanup_free_password) != PAM_SUCCESS) {
		pam_syslog(ph, LOG_ERR, "error storing password");
		return PAM_AUTHTOK_RECOVER_ERR;
	}

	if ((args & ARG_DEBUG) == ARG_DEBUG) {
		pam_syslog(ph, LOG_DEBUG, "password stored");
	}

	return PAM_SUCCESS;
}

/**
 * PAM function called during opening the session.
 *
 * Retrieves the password stored during authentication from PAM data, then uses
 * it set the cifs key.
 *
 * @param ph PAM handle
 * @param flags currently unused, TODO: check for silent flag
 * @param argc number of arguments for this PAM module
 * @param argv array of arguments for this PAM module
 * @return any of the PAM return values
 */
PAM_EXTERN int pam_sm_open_session(pam_handle_t *ph, int flags __attribute__((unused)), int argc, const char **argv)
{
	const char *user = NULL;
	const char *password = NULL;
	const char *hostdomain = NULL;
	uint args;
	int retval;
	key_serial_t	ses_key, uses_key;

	args = parse_args(ph, argc, argv, &hostdomain);

	/* Figure out the user name */
	retval = pam_get_user(ph, &user, NULL);
	if (retval != PAM_SUCCESS || !user) {
		pam_syslog(ph, LOG_ERR, "couldn't get the user name: %s",
			   pam_strerror(ph, retval));
		return PAM_SERVICE_ERR;
	}

	/* retrieve the stored password */
	if (pam_get_data(ph, "cifscreds_password", (const void**)&password) != PAM_SUCCESS) {
		/*
		 * No password, no worries, maybe this (PAM using) application
		 * didn't do authentication, or is hopeless and wants to call
		 * different PAM callbacks from different processes.
		 *
		 *
		 */
		password = NULL;
		if ((args & ARG_DEBUG) == ARG_DEBUG) {
			pam_syslog(ph, LOG_DEBUG, "no stored password found");
		}
		return PAM_SUCCESS;
	}

	/* make sure we have a host or domain name */
	if (!hostdomain) {
		pam_syslog(ph, LOG_ERR, "one of host= or domain= must be specified");
		return PAM_SERVICE_ERR;
	}

	/* make sure there is a session keyring */
	ses_key = keyctl_get_keyring_ID(KEY_SPEC_SESSION_KEYRING, 0);
	if (ses_key == -1) {
		if (errno == ENOKEY)
			pam_syslog(ph, LOG_ERR, "you have no session keyring. "
					"Consider using pam_keyinit to "
					"install one.");
		else
			pam_syslog(ph, LOG_ERR, "unable to query session "
					"keyring: %s", strerror(errno));
	}

	/* A problem querying the user-session keyring isn't fatal. */
	uses_key = keyctl_get_keyring_ID(KEY_SPEC_USER_SESSION_KEYRING, 0);
	if ((uses_key >= 0) && (ses_key == uses_key))
		pam_syslog(ph, LOG_ERR, "you have no persistent session "
				"keyring. cifscreds keys will not persist.");

	return cifscreds_pam_add(ph, user, password, args, hostdomain);
}

/**
 * This is called when the PAM session is closed.
 *
 * Currently it does nothing.  The session closing should remove the passwords
 *
 * @param ph PAM handle
 * @param flags currently unused, TODO: check for silent flag
 * @param argc number of arguments for this PAM module
 * @param argv array of arguments for this PAM module
 * @return PAM_SUCCESS
 */
PAM_EXTERN int pam_sm_close_session(pam_handle_t *ph __attribute__((unused)), int flags __attribute__((unused)), int argc __attribute__((unused)), const char **argv __attribute__((unused)))
{
	return PAM_SUCCESS;
}

/**
 * This is called when pam_set_cred() is invoked.
 *
 * @param ph PAM handle
 * @param flags currently unused, TODO: check for silent flag
 * @param argc number of arguments for this PAM module
 * @param argv array of arguments for this PAM module
 * @return PAM_SUCCESS
 */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *ph __attribute__((unused)), int flags __attribute__((unused)), int argc __attribute__((unused)), const char **argv __attribute__((unused)))
{
	return PAM_SUCCESS;
}

/**
 * This is called when the user's password is changed
 *
 * @param ph PAM handle
 * @param flags currently unused, TODO: check for silent flag
 * @param argc number of arguments for this PAM module
 * @param argv array of arguments for this PAM module
 * @return PAM_SUCCESS
 */
PAM_EXTERN int
pam_sm_chauthtok (pam_handle_t *ph, int flags, int argc, const char **argv)
{
	const char *hostdomain = NULL;
	const char *user = NULL;
	const char *password = NULL;
	uint args;
	int ret;

	args = parse_args(ph, argc, argv, &hostdomain);

	if (flags & PAM_UPDATE_AUTHTOK) {
		/* Figure out the user name */
		ret = pam_get_user(ph, &user, NULL);
		if (ret != PAM_SUCCESS) {
			pam_syslog(ph, LOG_ERR, "couldn't get the user name: %s", pam_strerror (ph, ret));
			return PAM_SERVICE_ERR;
		}

		ret = pam_get_item(ph, PAM_AUTHTOK, (const void**)&password);
		if (ret != PAM_SUCCESS || password == NULL) {
			if (ret == PAM_SUCCESS) {
				pam_syslog(ph, LOG_WARNING, "no password is available for user");
			} else {
				pam_syslog(ph, LOG_WARNING, "no password is available for user: %s", pam_strerror(ph, ret));
			}
			return PAM_AUTHTOK_RECOVER_ERR;
		}

		return cifscreds_pam_update(ph, user, password, args, hostdomain);
	}
	else
		return PAM_IGNORE;
}
