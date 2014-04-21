/*
 * Credentials stashing utility for Linux CIFS VFS (virtual filesystem) client
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <keyutils.h>
#include <getopt.h>
#include <errno.h>
#include "cifskey.h"
#include "mount.h"
#include "resolve_host.h"
#include "util.h"

#define THIS_PROGRAM_NAME "cifscreds"

/* max length of appropriate command */
#define MAX_COMMAND_SIZE 32

struct cmdarg {
	char		*host;
	char		*user;
	char		keytype;
};

struct command {
	int (*action)(struct cmdarg *arg);
	const char	name[MAX_COMMAND_SIZE];
	const char	*format;
};

static int cifscreds_add(struct cmdarg *arg);
static int cifscreds_clear(struct cmdarg *arg);
static int cifscreds_clearall(struct cmdarg *arg);
static int cifscreds_update(struct cmdarg *arg);

static const char *thisprogram;

static struct command commands[] = {
	{ cifscreds_add,	"add",		"[-u username] [-d] <host|domain>" },
	{ cifscreds_clear,	"clear",	"[-u username] [-d] <host|domain>" },
	{ cifscreds_clearall,	"clearall",	"" },
	{ cifscreds_update,	"update",	"[-u username] [-d] <host|domain>" },
	{ NULL, "", NULL }
};

static struct option longopts[] = {
	{"username", 1, NULL, 'u'},
	{"domain", 0, NULL, 'd' },
	{NULL, 0, NULL, 0}
};

/* display usage information */
static int
usage(void)
{
	struct command *cmd;

	fprintf(stderr, "Usage:\n");
	for (cmd = commands; cmd->action; cmd++)
		fprintf(stderr, "\t%s %s %s\n", thisprogram,
			cmd->name, cmd->format);
	fprintf(stderr, "\n");

	return EXIT_FAILURE;
}

/* search all program's keys in keyring */
static key_serial_t key_search_all(void)
{
	key_serial_t key, *pk;
	void *keylist;
	char *buffer;
	int count, dpos, n, ret;

	/* read the key payload data */
	count = keyctl_read_alloc(DEST_KEYRING, &keylist);
	if (count < 0)
		return 0;

	count /= sizeof(key_serial_t);

	if (count == 0) {
		ret = 0;
		goto key_search_all_out;
	}

	/* list the keys in the keyring */
	pk = keylist;
	do {
		key = *pk++;

		ret = keyctl_describe_alloc(key, &buffer);
		if (ret < 0)
			continue;

		n = sscanf(buffer, "%*[^;];%*d;%*d;%*x;%n", &dpos);
		if (n) {
			free(buffer);
			continue;
		}

		if (strstr(buffer + dpos, KEY_PREFIX ":") ==
			buffer + dpos
		) {
			ret = key;
			free(buffer);
			goto key_search_all_out;
		}
		free(buffer);

	} while (--count);

	ret = 0;

key_search_all_out:
	free(keylist);
	return ret;
}

/* add command handler */
static int cifscreds_add(struct cmdarg *arg)
{
	char addrstr[MAX_ADDR_LIST_LEN];
	char *currentaddress, *nextaddress;
	char *pass;
	int ret = 0;

	if (arg->host == NULL || arg->user == NULL)
		return usage();

	if (arg->keytype == 'd')
		strlcpy(addrstr, arg->host, MAX_ADDR_LIST_LEN);
	else
		ret = resolve_host(arg->host, addrstr);

	switch (ret) {
	case EX_USAGE:
		fprintf(stderr, "error: Could not resolve address "
			"for %s\n", arg->host);
		return EXIT_FAILURE;

	case EX_SYSERR:
		fprintf(stderr, "error: Problem parsing address list\n");
		return EXIT_FAILURE;
	}

	if (strpbrk(arg->user, USER_DISALLOWED_CHARS)) {
		fprintf(stderr, "error: Incorrect username\n");
		return EXIT_FAILURE;
	}

	/* search for same credentials stashed for current host */
	currentaddress = addrstr;
	nextaddress = strchr(currentaddress, ',');
	if (nextaddress)
		*nextaddress++ = '\0';

	while (currentaddress) {
		if (key_search(currentaddress, arg->keytype) > 0) {
			printf("You already have stashed credentials "
				"for %s (%s)\n", currentaddress, arg->host);
			printf("If you want to update them use:\n");
			printf("\t%s update\n", thisprogram);

			return EXIT_FAILURE;
		}

		switch(errno) {
		case ENOKEY:
			/* success */
			break;
		default:
			printf("Key search failed: %s\n", strerror(errno));
			return EXIT_FAILURE;
		}

		currentaddress = nextaddress;
		if (currentaddress) {
			*(currentaddress - 1) = ',';
			nextaddress = strchr(currentaddress, ',');
			if (nextaddress)
				*nextaddress++ = '\0';
		}
	}

	/*
	 * if there isn't same credentials stashed add them to keyring
	 * and set permisson mask
	 */
	pass = getpass("Password: ");

	currentaddress = addrstr;
	nextaddress = strchr(currentaddress, ',');
	if (nextaddress)
		*nextaddress++ = '\0';

	while (currentaddress) {
		key_serial_t key = key_add(currentaddress, arg->user, pass, arg->keytype);
		if (key <= 0) {
			fprintf(stderr, "error: Add credential key for %s: %s\n",
				currentaddress, strerror(errno));
		} else {
			if (keyctl(KEYCTL_SETPERM, key, CIFS_KEY_PERMS) < 0) {
				fprintf(stderr, "error: Setting permissons "
					"on key, attempt to delete...\n");

				if (keyctl(KEYCTL_UNLINK, key, DEST_KEYRING) < 0) {
					fprintf(stderr, "error: Deleting key from "
						"keyring for %s (%s)\n",
						currentaddress, arg->host);
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

	return EXIT_SUCCESS;
}

/* clear command handler */
static int cifscreds_clear(struct cmdarg *arg)
{
	char addrstr[MAX_ADDR_LIST_LEN];
	char *currentaddress, *nextaddress;
	int ret = 0, count = 0, errors = 0;

	if (arg->host == NULL || arg->user == NULL)
		return usage();

	if (arg->keytype == 'd')
		strlcpy(addrstr, arg->host, MAX_ADDR_LIST_LEN);
	else
		ret = resolve_host(arg->host, addrstr);

	switch (ret) {
	case EX_USAGE:
		fprintf(stderr, "error: Could not resolve address "
			"for %s\n", arg->host);
		return EXIT_FAILURE;

	case EX_SYSERR:
		fprintf(stderr, "error: Problem parsing address list\n");
		return EXIT_FAILURE;
	}

	if (strpbrk(arg->user, USER_DISALLOWED_CHARS)) {
		fprintf(stderr, "error: Incorrect username\n");
		return EXIT_FAILURE;
	}

	/*
	 * search for same credentials stashed for current host
	 * and unlink them from session keyring
	 */
	currentaddress = addrstr;
	nextaddress = strchr(currentaddress, ',');
	if (nextaddress)
		*nextaddress++ = '\0';

	while (currentaddress) {
		key_serial_t key = key_search(currentaddress, arg->keytype);
		if (key > 0) {
			if (keyctl(KEYCTL_UNLINK, key, DEST_KEYRING) < 0) {
				fprintf(stderr, "error: Removing key from "
					"keyring for %s (%s)\n",
					currentaddress, arg->host);
				errors++;
			} else {
				count++;
			}
		}

		currentaddress = nextaddress;
		if (currentaddress) {
			nextaddress = strchr(currentaddress, ',');
			if (nextaddress)
				*nextaddress++ = '\0';
		}
	}

	if (!count && !errors) {
		printf("You have no same stashed credentials "
			" for %s\n", arg->host);
		printf("If you want to add them use:\n");
		printf("\t%s add\n", thisprogram);

		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

/* clearall command handler */
static int cifscreds_clearall(struct cmdarg *arg __attribute__ ((unused)))
{
	key_serial_t key;
	int count = 0, errors = 0;

	/*
	 * search for all program's credentials stashed in session keyring
	 * and then unlink them
	 */
	do {
		key = key_search_all();
		if (key > 0) {
			if (keyctl(KEYCTL_UNLINK, key, DEST_KEYRING) < 0) {
				fprintf(stderr, "error: Deleting key "
					"from keyring");
				errors++;
			} else {
				count++;
			}
		}
	} while (key > 0);

	if (!count && !errors) {
		printf("You have no stashed " KEY_PREFIX
			" credentials\n");
		printf("If you want to add them use:\n");
		printf("\t%s add\n", thisprogram);

		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

/* update command handler */
static int cifscreds_update(struct cmdarg *arg)
{
	char addrstr[MAX_ADDR_LIST_LEN];
	char *currentaddress, *nextaddress, *pass;
	char *addrs[16];
	int ret = 0, id, count = 0;

	if (arg->host == NULL || arg->user == NULL)
		return usage();

	if (arg->keytype == 'd')
		strlcpy(addrstr, arg->host, MAX_ADDR_LIST_LEN);
	else
		ret = resolve_host(arg->host, addrstr);

	switch (ret) {
	case EX_USAGE:
		fprintf(stderr, "error: Could not resolve address "
			"for %s\n", arg->host);
		return EXIT_FAILURE;

	case EX_SYSERR:
		fprintf(stderr, "error: Problem parsing address list\n");
		return EXIT_FAILURE;
	}

	if (strpbrk(arg->user, USER_DISALLOWED_CHARS)) {
		fprintf(stderr, "error: Incorrect username\n");
		return EXIT_FAILURE;
	}

	/* search for necessary credentials stashed in session keyring */
	currentaddress = addrstr;
	nextaddress = strchr(currentaddress, ',');
	if (nextaddress)
		*nextaddress++ = '\0';

	while (currentaddress) {
		if (key_search(currentaddress, arg->keytype) > 0) {
			addrs[count] = currentaddress;
			count++;
		}

		currentaddress = nextaddress;
		if (currentaddress) {
			nextaddress = strchr(currentaddress, ',');
			if (nextaddress)
				*nextaddress++ = '\0';
		}
	}

	if (!count) {
		printf("You have no same stashed credentials "
			"for %s\n", arg->host);
		printf("If you want to add them use:\n");
		printf("\t%s add\n", thisprogram);

		return EXIT_FAILURE;
	}

	/* update payload of found keys */
	pass = getpass("Password: ");

	for (id = 0; id < count; id++) {
		key_serial_t key = key_add(addrs[id], arg->user, pass, arg->keytype);
		if (key <= 0)
			fprintf(stderr, "error: Update credential key "
				"for %s: %s\n", addrs[id], strerror(errno));
	}

	return EXIT_SUCCESS;
}

static int
check_session_keyring(void)
{
	key_serial_t	ses_key, uses_key;

	ses_key = keyctl_get_keyring_ID(KEY_SPEC_SESSION_KEYRING, 0);
	if (ses_key == -1) {
		if (errno == ENOKEY)
			fprintf(stderr, "Error: you have no session keyring. "
					"Consider using pam_keyinit to "
					"install one.\n");
		else
			fprintf(stderr, "Error: unable to query session "
					"keyring: %s\n", strerror(errno));
		return (int)ses_key;
	}

	/* A problem querying the user-session keyring isn't fatal. */
	uses_key = keyctl_get_keyring_ID(KEY_SPEC_USER_SESSION_KEYRING, 0);
	if (uses_key == -1)
		return 0;

	if (ses_key == uses_key)
		fprintf(stderr, "Warning: you have no persistent session "
				"keyring. cifscreds keys will not persist "
				"after this process exits. See "
				"pam_keyinit(8).\n");
	return 0;
}

int main(int argc, char **argv)
{
	struct command *cmd, *best;
	struct cmdarg arg;
	int n;

	memset(&arg, 0, sizeof(arg));
	arg.keytype = 'a';

	thisprogram = (char *)basename(argv[0]);
	if (thisprogram == NULL)
		thisprogram = THIS_PROGRAM_NAME;

	if (argc == 1)
		return usage();

	while((n = getopt_long(argc, argv, "du:", longopts, NULL)) != -1) {
		switch (n) {
		case 'd':
			arg.keytype = (char) n;
			break;
		case 'u':
			arg.user = optarg;
			break;
		default:
			return usage();
		}
	}

	/* find the best fit command */
	best = NULL;
	n = strnlen(argv[optind], MAX_COMMAND_SIZE);

	for (cmd = commands; cmd->action; cmd++) {
		if (memcmp(cmd->name, argv[optind], n) != 0)
			continue;

		if (cmd->name[n] == 0) {
			/* exact match */
			best = cmd;
			break;
		}

		/* partial match */
		if (best) {
			fprintf(stderr, "Ambiguous command\n");
			return EXIT_FAILURE;
		}

		best = cmd;
	}

	if (!best) {
		fprintf(stderr, "Unknown command\n");
		return EXIT_FAILURE;
	}

	/* second argument should be host or domain */
	if (argc >= 3)
		arg.host = argv[optind + 1];

	if (arg.host && arg.keytype == 'd' &&
	    strpbrk(arg.host, DOMAIN_DISALLOWED_CHARS)) {
		fprintf(stderr, "error: Domain name contains invalid characters\n");
		return EXIT_FAILURE;
	}

	if (arg.user == NULL)
		arg.user = getusername(getuid());

	if (check_session_keyring())
		return EXIT_FAILURE;

	return best->action(&arg);
}
