/*
 * Mount helper utility for Linux CIFS VFS (virtual filesystem) client
 * Copyright (C) 2003,2008 Steve French  (sfrench@us.ibm.com)
 * Copyright (C) 2008 Jeremy Allison (jra@samba.org)
 * Copyright (C) 2010 Jeff Layton (jlayton@samba.org)
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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <mntent.h>
#include <fcntl.h>
#include <limits.h>
#include <fstab.h>
#include <sys/mman.h>
#include <sys/wait.h>
#ifdef HAVE_LIBCAP_NG
#include <cap-ng.h>
#else /* HAVE_LIBCAP_NG */
#ifdef HAVE_LIBCAP
#include <sys/capability.h>
#endif /* HAVE_LIBCAP */
#endif /* HAVE_LIBCAP_NG */
#include "mount.h"
#include "util.h"

#ifndef MS_MOVE 
#define MS_MOVE 8192 
#endif 

#ifndef MS_BIND
#define MS_BIND 4096
#endif

/* private flags - clear these before passing to kernel */
#define MS_USERS	0x40000000
#define MS_USER		0x80000000

#define MAX_UNC_LEN 1024

/* I believe that the kernel limits options data to a page */
#define MAX_OPTIONS_LEN	4096

/* max length of mtab options */
#define MTAB_OPTIONS_LEN 220

/*
 * Maximum length of "share" portion of a UNC. I have no idea if this is at
 * all valid. According to MSDN, the typical max length of any component is
 * 255, so use that here.
 */
#define MAX_SHARE_LEN 256

/* max length of username (somewhat made up here) */
#define MAX_USERNAME_SIZE 32

/* currently maximum length of IPv6 address string */
#define MAX_ADDRESS_LEN INET6_ADDRSTRLEN

/* limit list of addresses to 16 max-size addrs */
#define MAX_ADDR_LIST_LEN ((MAX_ADDRESS_LEN + 1) * 16)

#ifndef SAFE_FREE
#define SAFE_FREE(x) do { if ((x) != NULL) {free(x); x = NULL; } } while (0)
#endif

#define MOUNT_PASSWD_SIZE 128
#define DOMAIN_SIZE 64

/*
 * value of the ver= option that gets passed to the kernel. Used to indicate
 * behavioral changes introduced in the mount helper.
 */
#define OPTIONS_VERSION "1"

/*
 * mount.cifs has been the subject of many "security" bugs that have arisen
 * because of users and distributions installing it as a setuid root program
 * before it had been audited for security holes. The default behavior is
 * now to allow mount.cifs to be run as a setuid root program. Some admins
 * may want to disable this fully, so this switch remains in place.
 */
#define CIFS_DISABLE_SETUID_CAPABILITY 0

/*
 * When an unprivileged user runs a setuid mount.cifs, we set certain mount
 * flags by default. These defaults can be changed here.
 */
#define CIFS_SETUID_FLAGS (MS_NOSUID|MS_NODEV)

/* struct for holding parsed mount info for use by privleged process */
struct parsed_mount_info {
	unsigned long flags;
	char host[NI_MAXHOST + 1];
	char share[MAX_SHARE_LEN + 1];
	char prefix[PATH_MAX + 1];
	char options[MAX_OPTIONS_LEN];
	char domain[DOMAIN_SIZE + 1];
	char username[MAX_USERNAME_SIZE + 1];
	char password[MOUNT_PASSWD_SIZE + 1];
	char addrlist[MAX_ADDR_LIST_LEN];
	unsigned int got_user:1;
	unsigned int got_password:1;
	unsigned int fakemnt:1;
	unsigned int nomtab:1;
	unsigned int verboseflag:1;
};

const char *thisprogram;
const char *cifs_fstype = "cifs";

static int parse_unc(const char *unc_name, struct parsed_mount_info *parsed_info);

static int check_setuid(void)
{
	if (geteuid()) {
		fprintf(stderr, "This program is not installed setuid root - "
			" \"user\" CIFS mounts not supported.\n");
		return EX_USAGE;
	}

#if CIFS_DISABLE_SETUID_CAPABILITY
	if (getuid() && !geteuid()) {
		printf("This mount.cifs program has been built with the "
		       "ability to run as a setuid root program disabled.\n");
		return EX_USAGE;
	}
#endif /* CIFS_DISABLE_SETUID_CAPABILITY */

	return 0;
}

static int
check_fstab(const char *progname, const char *mountpoint, const char *devname,
	    char **options)
{
	FILE *fstab;
	struct mntent *mnt;

	/* make sure this mount is listed in /etc/fstab */
	fstab = setmntent(_PATH_FSTAB, "r");
	if (!fstab) {
		fprintf(stderr, "Couldn't open %s for reading!\n", _PATH_FSTAB);
		return EX_FILEIO;
	}

	while ((mnt = getmntent(fstab))) {
		if (!strcmp(mountpoint, mnt->mnt_dir))
			break;
	}
	endmntent(fstab);

	if (mnt == NULL || strcmp(mnt->mnt_fsname, devname)) {
		fprintf(stderr, "%s: permission denied: no match for "
			"%s found in %s\n", progname, mountpoint, _PATH_FSTAB);
		return EX_USAGE;
	}

	/*
	 * 'mount' munges the options from fstab before passing them
	 * to us. It is non-trivial to test that we have the correct
	 * set of options. We don't want to trust what the user
	 * gave us, so just take whatever is in /etc/fstab.
	 */
	free(*options);
	*options = strdup(mnt->mnt_opts);
	return 0;
}

/* BB finish BB

	cifs_umount
	open nofollow - avoid symlink exposure? 
	get owner of dir see if matches self or if root
	call system(umount argv) etc.

BB end finish BB */

static int mount_cifs_usage(FILE * stream)
{
	fprintf(stream, "\nUsage:  %s <remotetarget> <dir> -o <options>\n",
		thisprogram);
	fprintf(stream, "\nMount the remote target, specified as a UNC name,");
	fprintf(stream, " to a local directory.\n\nOptions:\n");
	fprintf(stream, "\tuser=<arg>\n\tpass=<arg>\n\tdom=<arg>\n");
	fprintf(stream, "\nLess commonly used options:");
	fprintf(stream,
		"\n\tcredentials=<filename>,guest,perm,noperm,setuids,nosetuids,rw,ro,");
	fprintf(stream,
		"\n\tsep=<char>,iocharset=<codepage>,suid,nosuid,exec,noexec,serverino,");
	fprintf(stream,
		"\n\tmapchars,nomapchars,nolock,servernetbiosname=<SRV_RFC1001NAME>");
	fprintf(stream,
		"\n\tdirectio,nounix,cifsacl,sec=<authentication mechanism>,sign");
	fprintf(stream,
		"\n\nOptions not needed for servers supporting CIFS Unix extensions");
	fprintf(stream,
		"\n\t(e.g. unneeded for mounts to most Samba versions):");
	fprintf(stream,
		"\n\tuid=<uid>,gid=<gid>,dir_mode=<mode>,file_mode=<mode>,sfu");
	fprintf(stream, "\n\nRarely used options:");
	fprintf(stream,
		"\n\tport=<tcpport>,rsize=<size>,wsize=<size>,unc=<unc_name>,ip=<ip_address>,");
	fprintf(stream,
		"\n\tdev,nodev,nouser_xattr,netbiosname=<OUR_RFC1001NAME>,hard,soft,intr,");
	fprintf(stream,
		"\n\tnointr,ignorecase,noposixpaths,noacl,prefixpath=<path>,nobrl");
	fprintf(stream,
		"\n\nOptions are described in more detail in the manual page");
	fprintf(stream, "\n\tman 8 mount.cifs\n");
	fprintf(stream, "\nTo display the version number of the mount helper:");
	fprintf(stream, "\n\t%s -V\n", thisprogram);

	if (stream == stderr)
		return EX_USAGE;
	return 0;
}

/*
 * CIFS has to "escape" commas in the password field so that they don't
 * end up getting confused for option delimiters. Copy password into pw
 * field, turning any commas into double commas.
 */
static int set_password(struct parsed_mount_info *parsed_info, const char *src)
{
	char *dst = parsed_info->password;
	unsigned int i = 0, j = 0;

	while (src[i]) {
		if (src[i] == ',')
			dst[j++] = ',';
		dst[j++] = src[i++];
		if (j > sizeof(parsed_info->password)) {
			fprintf(stderr, "Converted password too long!\n");
			return EX_USAGE;
		}
	}
	dst[j] = '\0';
	parsed_info->got_password = 1;
	return 0;
}

/* caller frees username if necessary */
static char *getusername(uid_t uid)
{
	char *username = NULL;
	struct passwd *password = getpwuid(uid);

	if (password)
		username = password->pw_name;
	return username;
}

/*
 * Parse a username string into parsed_mount_info fields. The format is:
 *
 * DOMAIN\username%password
 *
 * ...obviously the only required component is "username". The source string
 * is modified in the process, but it should remain unchanged at the end.
 */
static int parse_username(char *rawuser, struct parsed_mount_info *parsed_info)
{
	char *user, *password, slash;
	int rc = 0;

	/* everything after first % sign is a password */
	password = strchr(rawuser, '%');
	if (password) {
		rc = set_password(parsed_info, password);
		if (rc)
			return rc;
	}

	/* everything after first '/' or '\' is a username */
	user = strchr(rawuser, '/');
	if (!user)
		user = strchr(rawuser, '\\');

	/* everything before that slash is a domain */
	if (user) {
		slash = *user;
		*user = '\0';
		strlcpy(parsed_info->domain, rawuser,
			sizeof(parsed_info->domain));
		*(user++) = slash;
	} else {
		user = rawuser;
	}

	strlcpy(parsed_info->username, user, sizeof(parsed_info->username));
	parsed_info->got_user = 1;
	if (password)
		*password = '%';

	return 0;
}

#ifdef HAVE_LIBCAP_NG
static int
drop_capabilities(int parent)
{
	capng_setpid(getpid());
	capng_clear(CAPNG_SELECT_BOTH);
	if (capng_update(CAPNG_ADD, CAPNG_PERMITTED, CAP_DAC_OVERRIDE)) {
		fprintf(stderr, "Unable to update capability set.\n");
		return EX_SYSERR;
	}

	if (parent) {
		if (capng_update(CAPNG_ADD, CAPNG_PERMITTED|CAPNG_EFFECTIVE, CAP_SYS_ADMIN)) {
			fprintf(stderr, "Unable to update capability set.\n");
			return EX_SYSERR;
		}
	}
	if (capng_apply(CAPNG_SELECT_BOTH)) {
		fprintf(stderr, "Unable to apply new capability set.\n");
		return EX_SYSERR;
	}
	return 0;
}

static int
toggle_cap_dac_override(int enable)
{
	if (capng_update(enable ? CAPNG_ADD : CAPNG_DROP, CAPNG_EFFECTIVE, CAP_DAC_OVERRIDE)) {
		fprintf(stderr, "Unable to update capability set.\n");
		return EX_SYSERR;
	}
	if (capng_apply(CAPNG_SELECT_CAPS)) {
		fprintf(stderr, "Unable to apply new capability set.\n");
		return EX_SYSERR;
	}
	return 0;
}
#else /* HAVE_LIBCAP_NG */
#ifdef HAVE_LIBCAP
static int
drop_capabilities(int parent)
{
	int rc = 0, ncaps;
	cap_t caps;
	cap_value_t cap_list[2];

	caps = cap_get_proc();
	if (caps == NULL) {
		fprintf(stderr, "Unable to get current capability set: %s\n",
			strerror(errno));
		return EX_SYSERR;
	}

	if (cap_clear(caps) == -1) {
		fprintf(stderr, "Unable to clear capability set: %s\n",
			strerror(errno));
		rc = EX_SYSERR;
		goto free_caps;
	}

	if (parent || getuid() == 0) {
		ncaps = 1;
		cap_list[0] = CAP_DAC_OVERRIDE;
		if (parent) {
			cap_list[1] = CAP_SYS_ADMIN;
			++ncaps;
		}
		if (cap_set_flag(caps, CAP_PERMITTED, ncaps, cap_list, CAP_SET) == -1) {
			fprintf(stderr, "Unable to set permitted capabilities: %s\n",
				strerror(errno));
			rc = EX_SYSERR;
			goto free_caps;
		}
		if (parent) {
			cap_list[0] = CAP_SYS_ADMIN;
			if (cap_set_flag(caps, CAP_EFFECTIVE, 1, cap_list, CAP_SET) == -1) {
				fprintf(stderr, "Unable to set effective capabilities: %s\n",
					strerror(errno));
				rc = EX_SYSERR;
				goto free_caps;
			}
		}
	}

	if (cap_set_proc(caps) != 0) {
		fprintf(stderr, "Unable to set current process capabilities: %s\n",
			strerror(errno));
		rc = EX_SYSERR;
	}
free_caps:
	cap_free(caps);
	return rc;
}

static int
toggle_cap_dac_override(int enable)
{
	int rc;
	cap_t caps;
	cap_value_t cap_list;

	if (getuid() != 0)
		return 0;

	caps = cap_get_proc();
	if (caps == NULL) {
		fprintf(stderr, "Unable to get current capability set: %s\n",
			strerror(errno));
		return EX_SYSERR;
	}

	cap_list = CAP_DAC_OVERRIDE;
	if (cap_set_flag(caps, CAP_EFFECTIVE, 1, &cap_list,
			 enable ? CAP_SET : CAP_CLEAR) == -1) {
		fprintf(stderr, "Unable to %s effective capabilities: %s\n",
			enable ? "set" : "clear", strerror(errno));
		rc = EX_SYSERR;
		goto free_caps;
	}

	if (cap_set_proc(caps) != 0) {
		fprintf(stderr, "Unable to set current process capabilities: %s\n",
			strerror(errno));
		rc = EX_SYSERR;
	}
free_caps:
	cap_free(caps);
	return 0;
}
#else /* HAVE_LIBCAP */
static int
drop_capabilities(int parent)
{
	return 0;
}

static int
toggle_cap_dac_override(int enable)
{
	return 0;
}
#endif /* HAVE_LIBCAP */
#endif /* HAVE_LIBCAP_NG */

static int open_cred_file(char *file_name,
			  struct parsed_mount_info *parsed_info)
{
	char *line_buf;
	char *temp_val, *newline;
	FILE *fs = NULL;
	int i, length;

	i = toggle_cap_dac_override(1);
	if (i)
		return i;

	i = access(file_name, R_OK);
	if (i) {
		toggle_cap_dac_override(0);
		return i;
	}

	fs = fopen(file_name, "r");
	if (fs == NULL) {
		toggle_cap_dac_override(0);
		return errno;
	}

	i = toggle_cap_dac_override(0);
	if (i) {
		fclose(fs);
		return i;
	}

	line_buf = (char *)malloc(4096);
	if (line_buf == NULL) {
		fclose(fs);
		return EX_SYSERR;
	}

	while (fgets(line_buf, 4096, fs)) {
		/* parse line from credential file */

		/* eat leading white space */
		for (i = 0; i < 4086; i++) {
			if ((line_buf[i] != ' ') && (line_buf[i] != '\t'))
				break;
			/* if whitespace - skip past it */
		}

		/* NULL terminate at newline */
		newline = strchr(line_buf + i, '\n');
		if (newline)
			*newline = '\0';

		if (strncasecmp("username", line_buf + i, 8) == 0) {
			temp_val = strchr(line_buf + i, '=');
			if (temp_val) {
				/* go past equals sign */
				temp_val++;
				for (length = 0; length < 4087; length++) {
					if ((temp_val[length] == '\n')
					    || (temp_val[length] == '\0')) {
						temp_val[length] = '\0';
						break;
					}
				}
				if (length > 4086) {
					fprintf(stderr,
						"mount.cifs failed due to malformed username in credentials file\n");
					memset(line_buf, 0, 4096);
					return EX_USAGE;
				}
				parsed_info->got_user = 1;
				strlcpy(parsed_info->username, temp_val,
					sizeof(parsed_info->username));
			}
		} else if (strncasecmp("password", line_buf + i, 8) == 0) {
			temp_val = strchr(line_buf + i, '=');
			if (!temp_val)
				continue;
			++temp_val;
			i = set_password(parsed_info, temp_val);
			if (i)
				return i;
		} else if (strncasecmp("domain", line_buf + i, 6) == 0) {
			temp_val = strchr(line_buf + i, '=');
			if (temp_val) {
				/* go past equals sign */
				temp_val++;
				if (parsed_info->verboseflag)
					fprintf(stderr, "\nDomain %s\n",
						temp_val);

				for (length = 0; length < DOMAIN_SIZE + 1;
				     length++) {
					if ((temp_val[length] == '\n')
					    || (temp_val[length] == '\0')) {
						temp_val[length] = '\0';
						break;
					}
				}

				if (length > DOMAIN_SIZE) {
					fprintf(stderr,
						"mount.cifs failed: domain in credentials file too long\n");
					return EX_USAGE;
				}

				strlcpy(parsed_info->domain, temp_val,
					sizeof(parsed_info->domain));
			}
		}

	}
	fclose(fs);
	SAFE_FREE(line_buf);
	return 0;
}

static int
get_password_from_file(int file_descript, char *filename,
		       struct parsed_mount_info *parsed_info)
{
	int rc = 0;
	char buf[sizeof(parsed_info->password) + 1];

	if (filename != NULL) {
		rc = toggle_cap_dac_override(1);
		if (rc)
			return rc;

		rc = access(filename, R_OK);
		if (rc) {
			fprintf(stderr,
				"mount.cifs failed: access check of %s failed: %s\n",
				filename, strerror(errno));
			toggle_cap_dac_override(0);
			return EX_SYSERR;
		}

		file_descript = open(filename, O_RDONLY);
		if (file_descript < 0) {
			fprintf(stderr,
				"mount.cifs failed. %s attempting to open password file %s\n",
				strerror(errno), filename);
			toggle_cap_dac_override(0);
			return EX_SYSERR;
		}

		rc = toggle_cap_dac_override(0);
		if (rc) {
			rc = EX_SYSERR;
			goto get_pw_exit;
		}
	}

	memset(buf, 0, sizeof(buf));
	rc = read(file_descript, buf, sizeof(buf) - 1);
	if (rc < 0) {
		fprintf(stderr,
			"mount.cifs failed. Error %s reading password file\n",
			strerror(errno));
		rc = EX_SYSERR;
		goto get_pw_exit;
	}

	rc = set_password(parsed_info, buf);

get_pw_exit:
	if (filename != NULL)
		close(file_descript);
	return rc;
}

static int
parse_options(const char *data, struct parsed_mount_info *parsed_info)
{
	char *value = NULL, *equals = NULL;
	char *next_keyword = NULL;
	char *out = parsed_info->options;
	unsigned long *filesys_flags = &parsed_info->flags;
	int out_len = 0;
	int word_len;
	int rc = 0;
	int got_uid = 0, got_gid = 0;
	char user[32];
	char group[32];

	/* make sure we're starting from beginning */
	out[0] = '\0';

	/* BB fixme check for separator override BB */
	if (getuid()) {
		got_uid = 1;
		snprintf(user, sizeof(user), "%u", getuid());
		got_gid = 1;
		snprintf(group, sizeof(group), "%u", getgid());
	}

	if (!data)
		return EX_USAGE;

	/*
	 * format is keyword,keyword2=value2,keyword3=value3... 
	 * data  = next keyword
	 * value = next value ie stuff after equal sign
	 */
	while (data && *data) {
		next_keyword = strchr(data, ',');	/* BB handle sep= */

		/* temporarily null terminate end of keyword=value pair */
		if (next_keyword)
			*next_keyword++ = 0;

		/* temporarily null terminate keyword if there's a value */
		value = NULL;
		if ((equals = strchr(data, '=')) != NULL) {
			*equals = '\0';
			value = equals + 1;
		}

		/* FIXME: turn into a token parser? */
		if (strncmp(data, "users", 5) == 0) {
			if (!value || !*value) {
				*filesys_flags |= MS_USERS;
				goto nocopy;
			}
		} else if (strncmp(data, "user_xattr", 10) == 0) {
			/* do nothing - need to skip so not parsed as user name */
		} else if (strncmp(data, "user", 4) == 0) {
			if (!value || !*value) {
				if (data[4] == '\0') {
					*filesys_flags |= MS_USER;
					goto nocopy;
				} else {
					fprintf(stderr,
						"username specified with no parameter\n");
					return EX_USAGE;
				}
			} else {
				if (strnlen(value, 260) >= 260) {
					fprintf(stderr, "username too long\n");
					return EX_USAGE;
				}
				rc = parse_username(value, parsed_info);
				if (rc) {
					fprintf(stderr,
						"problem parsing username\n");
					return rc;
				}
				goto nocopy;
			}
		} else if (strncmp(data, "pass", 4) == 0) {
			if (parsed_info->got_password) {
				fprintf(stderr,
					"password specified twice, ignoring second\n");
				goto nocopy;
			}
			if (!value || !*value) {
				parsed_info->got_password = 1;
				goto nocopy;
			}
			rc = set_password(parsed_info, value);
			if (rc)
				return rc;
			goto nocopy;
		} else if (strncmp(data, "sec", 3) == 0) {
			if (value) {
				if (!strncmp(value, "none", 4) ||
				    !strncmp(value, "krb5", 4))
					parsed_info->got_password = 1;
			}
		} else if (strncmp(data, "ip", 2) == 0) {
			if (!value || !*value) {
				fprintf(stderr,
					"target ip address argument missing");
			} else if (strnlen(value, MAX_ADDRESS_LEN) <=
				   MAX_ADDRESS_LEN) {
				if (parsed_info->verboseflag)
					fprintf(stderr,
						"ip address %s override specified\n",
						value);
			} else {
				fprintf(stderr, "ip address too long\n");
				return EX_USAGE;
			}
		} else if ((strncmp(data, "unc", 3) == 0)
			   || (strncmp(data, "target", 6) == 0)
			   || (strncmp(data, "path", 4) == 0)) {
			if (!value || !*value) {
				fprintf(stderr,
					"invalid path to network resource\n");
				return EX_USAGE;	/* needs_arg; */
			}
			rc = parse_unc(value, parsed_info);
			if (rc)
				return rc;
		} else if ((strncmp(data, "dom" /* domain */ , 3) == 0)
			   || (strncmp(data, "workg", 5) == 0)) {
			/* note this allows for synonyms of "domain"
			   such as "DOM" and "dom" and "workgroup"
			   and "WORKGRP" etc. */
			if (!value || !*value) {
				fprintf(stderr, "CIFS: invalid domain name\n");
				return EX_USAGE;
			}
			if (strnlen(value, sizeof(parsed_info->domain)) >=
			    sizeof(parsed_info->domain)) {
				fprintf(stderr, "domain name too long\n");
				return EX_USAGE;
			}
			strlcpy(parsed_info->domain, value,
				sizeof(parsed_info->domain));
			goto nocopy;
		} else if (strncmp(data, "cred", 4) == 0) {
			if (value && *value) {
				rc = open_cred_file(value, parsed_info);
				if (rc) {
					fprintf(stderr,
						"error %d (%s) opening credential file %s\n",
						rc, strerror(rc), value);
					return rc;
				}
			} else {
				fprintf(stderr,
					"invalid credential file name specified\n");
				return EX_USAGE;
			}
		} else if (strncmp(data, "uid", 3) == 0) {
			if (value && *value) {
				got_uid = 1;
				if (!isdigit(*value)) {
					struct passwd *pw;

					if (!(pw = getpwnam(value))) {
						fprintf(stderr,
							"bad user name \"%s\"\n",
							value);
						return EX_USAGE;
					}
					snprintf(user, sizeof(user), "%u",
						 pw->pw_uid);
				} else {
					strlcpy(user, value, sizeof(user));
				}
			}
			goto nocopy;
		} else if (strncmp(data, "gid", 3) == 0) {
			if (value && *value) {
				got_gid = 1;
				if (!isdigit(*value)) {
					struct group *gr;

					if (!(gr = getgrnam(value))) {
						fprintf(stderr,
							"bad group name \"%s\"\n",
							value);
						return EX_USAGE;
					}
					snprintf(group, sizeof(group), "%u",
						 gr->gr_gid);
				} else {
					strlcpy(group, value, sizeof(group));
				}
			}
			goto nocopy;
			/* fmask and dmask synonyms for people used to smbfs syntax */
		} else if (strcmp(data, "file_mode") == 0
			   || strcmp(data, "fmask") == 0) {
			if (!value || !*value) {
				fprintf(stderr,
					"Option '%s' requires a numerical argument\n",
					data);
				return EX_USAGE;
			}

			if (value[0] != '0') {
				fprintf(stderr,
					"WARNING: '%s' not expressed in octal.\n",
					data);
			}

			if (strcmp(data, "fmask") == 0) {
				fprintf(stderr,
					"WARNING: CIFS mount option 'fmask' is deprecated. Use 'file_mode' instead.\n");
				data = "file_mode";	/* BB fix this */
			}
		} else if (strcmp(data, "dir_mode") == 0
			   || strcmp(data, "dmask") == 0) {
			if (!value || !*value) {
				fprintf(stderr,
					"Option '%s' requires a numerical argument\n",
					data);
				return EX_USAGE;
			}

			if (value[0] != '0') {
				fprintf(stderr,
					"WARNING: '%s' not expressed in octal.\n",
					data);
			}

			if (strcmp(data, "dmask") == 0) {
				fprintf(stderr,
					"WARNING: CIFS mount option 'dmask' is deprecated. Use 'dir_mode' instead.\n");
				data = "dir_mode";
			}
			/* the following eight mount options should be
			   stripped out from what is passed into the kernel
			   since these eight options are best passed as the
			   mount flags rather than redundantly to the kernel 
			   and could generate spurious warnings depending on the
			   level of the corresponding cifs vfs kernel code */
		} else if (strncmp(data, "nosuid", 6) == 0) {
			*filesys_flags |= MS_NOSUID;
		} else if (strncmp(data, "suid", 4) == 0) {
			*filesys_flags &= ~MS_NOSUID;
		} else if (strncmp(data, "nodev", 5) == 0) {
			*filesys_flags |= MS_NODEV;
		} else if ((strncmp(data, "nobrl", 5) == 0) ||
			   (strncmp(data, "nolock", 6) == 0)) {
			*filesys_flags &= ~MS_MANDLOCK;
		} else if (strncmp(data, "dev", 3) == 0) {
			*filesys_flags &= ~MS_NODEV;
		} else if (strncmp(data, "noexec", 6) == 0) {
			*filesys_flags |= MS_NOEXEC;
		} else if (strncmp(data, "exec", 4) == 0) {
			*filesys_flags &= ~MS_NOEXEC;
		} else if (strncmp(data, "guest", 5) == 0) {
			parsed_info->got_user = 1;
			parsed_info->got_password = 1;
		} else if (strncmp(data, "ro", 2) == 0) {
			*filesys_flags |= MS_RDONLY;
			goto nocopy;
		} else if (strncmp(data, "rw", 2) == 0) {
			*filesys_flags &= ~MS_RDONLY;
			goto nocopy;
		} else if (strncmp(data, "remount", 7) == 0) {
			*filesys_flags |= MS_REMOUNT;
		}

		/* check size before copying option to buffer */
		word_len = strlen(data);
		if (value)
			word_len += 1 + strlen(value);

		/* need 2 extra bytes for comma and null byte */
		if (out_len + word_len + 2 > MAX_OPTIONS_LEN) {
			fprintf(stderr, "Options string too long\n");
			return EX_USAGE;
		}

		/* put back equals sign, if any */
		if (equals)
			*equals = '=';

		/* go ahead and copy */
		if (out_len)
			strlcat(out, ",", MAX_OPTIONS_LEN);

		strlcat(out, data, MAX_OPTIONS_LEN);
		out_len = strlen(out);
nocopy:
		data = next_keyword;
	}

	/* special-case the uid and gid */
	if (got_uid) {
		word_len = strlen(user);

		if (out_len + word_len + 6 > MAX_OPTIONS_LEN) {
			fprintf(stderr, "Options string too long\n");
			return EX_USAGE;
		}

		if (out_len) {
			strlcat(out, ",", out_len + word_len + 6);
			out_len++;
		}
		snprintf(out + out_len, word_len + 5, "uid=%s", user);
		out_len = strlen(out);
	}
	if (got_gid) {
		word_len = strlen(group);

		if (out_len + 1 + word_len + 6 > MAX_OPTIONS_LEN) {
			fprintf(stderr, "Options string too long\n");
			return EX_USAGE;
		}

		if (out_len) {
			strlcat(out, ",", out_len + word_len + 6);
			out_len++;
		}
		snprintf(out + out_len, word_len + 5, "gid=%s", group);
		out_len = strlen(out);
	}

	return 0;
}

/*
 * resolve "host" portion of parsed info to comma-separated list of
 * address(es)
 */
static int resolve_host(struct parsed_mount_info *parsed_info)
{
	int rc;
	/* 10 for max width of decimal scopeid */
	char tmpbuf[NI_MAXHOST + 1 + 10 + 1];
	const char *ipaddr;
	size_t len;
	struct addrinfo *addrlist, *addr;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;

	rc = getaddrinfo(parsed_info->host, NULL, NULL, &addrlist);
	if (rc != 0) {
		fprintf(stderr, "mount error: could not resolve address for "
			"%s: %s\n", parsed_info->host,
			rc == EAI_SYSTEM ? strerror(errno) : gai_strerror(rc));
		/* FIXME: return better error based on rc? */
		return EX_USAGE;
	}

	addr = addrlist;
	while (addr) {
		/* skip non-TCP entries */
		if (addr->ai_socktype != SOCK_STREAM ||
		    addr->ai_protocol != IPPROTO_TCP) {
			addr = addr->ai_next;
			continue;
		}

		switch (addr->ai_addr->sa_family) {
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)addr->ai_addr;
			ipaddr = inet_ntop(AF_INET6, &sin6->sin6_addr, tmpbuf,
					   sizeof(tmpbuf));
			if (!ipaddr) {
				rc = EX_SYSERR;
				fprintf(stderr,
					"mount error: problem parsing address "
					"list: %s\n", strerror(errno));
				goto resolve_host_out;
			}

			if (sin6->sin6_scope_id) {
				len = strnlen(tmpbuf, sizeof(tmpbuf));
				ipaddr = tmpbuf + len;
				snprintf(tmpbuf, sizeof(tmpbuf) - len, "%%%u",
					 sin6->sin6_scope_id);
			}
			break;
		case AF_INET:
			sin = (struct sockaddr_in *)addr->ai_addr;
			ipaddr = inet_ntop(AF_INET, &sin->sin_addr, tmpbuf,
					   sizeof(tmpbuf));
			if (!ipaddr) {
				rc = EX_SYSERR;
				fprintf(stderr,
					"mount error: problem parsing address "
					"list: %s\n", strerror(errno));
				goto resolve_host_out;
			}

			break;
		default:
			addr = addr->ai_next;
			continue;
		}

		if (parsed_info->addrlist[0] != '\0')
			strlcat(parsed_info->addrlist, ",",
				sizeof(parsed_info->addrlist));
		strlcat(parsed_info->addrlist, tmpbuf,
			sizeof(parsed_info->addrlist));
		addr = addr->ai_next;
	}

resolve_host_out:
	freeaddrinfo(addrlist);
	return rc;
}

static int parse_unc(const char *unc_name, struct parsed_mount_info *parsed_info)
{
	int length = strnlen(unc_name, MAX_UNC_LEN);
	const char *host, *share, *prepath;
	size_t hostlen, sharelen, prepathlen;

	if (length > (MAX_UNC_LEN - 1)) {
		fprintf(stderr, "mount error: UNC name too long\n");
		return EX_USAGE;
	}

	if (length < 3) {
		fprintf(stderr, "mount error: UNC name too short\n");
		return EX_USAGE;
	}

	if ((strncasecmp("cifs://", unc_name, 7) == 0) ||
	    (strncasecmp("smb://", unc_name, 6) == 0)) {
		fprintf(stderr,
			"Mounting cifs URL not implemented yet. Attempt to mount %s\n",
			unc_name);
		return EX_USAGE;
	}

	/* Set up "host" and "share" pointers based on UNC format. */
	if (strncmp(unc_name, "//", 2) && strncmp(unc_name, "\\\\", 2)) {
		/*
		 * check for nfs syntax (server:/share/prepath)
		 *
		 * FIXME: IPv6 addresses?
		 */
		host = unc_name;
		share = strchr(host, ':');
		if (!share) {
			fprintf(stderr, "mount.cifs: bad UNC (%s)\n", unc_name);
			return EX_USAGE;
		}
		hostlen = share - host;
		share++;
		if (*share == '/')
			++share;
	} else {
		host = unc_name + 2;
		hostlen = strcspn(host, "/\\");
		if (!hostlen) {
			fprintf(stderr, "mount.cifs: bad UNC (%s)\n", unc_name);
			return EX_USAGE;
		}
		share = host + hostlen + 1;
	}

	if (hostlen + 1 > sizeof(parsed_info->host)) {
		fprintf(stderr, "mount.cifs: host portion of UNC too long\n");
		return EX_USAGE;
	}

	sharelen = strcspn(share, "/\\");
	if (sharelen + 1 > sizeof(parsed_info->share)) {
		fprintf(stderr, "mount.cifs: share portion of UNC too long\n");
		return EX_USAGE;
	}

	prepath = share + sharelen;
	prepathlen = strlen(prepath);

	if (prepathlen + 1 > sizeof(parsed_info->prefix)) {
		fprintf(stderr, "mount.cifs: UNC prefixpath too long\n");
		return EX_USAGE;
	}

	/* copy pieces into their resepective buffers */
	memcpy(parsed_info->host, host, hostlen);
	memcpy(parsed_info->share, share, sharelen);
	memcpy(parsed_info->prefix, prepath, prepathlen);

	return 0;
}

static int get_pw_from_env(struct parsed_mount_info *parsed_info)
{
	int rc = 0;

	if (getenv("PASSWD"))
		rc = set_password(parsed_info, getenv("PASSWD"));
	else if (getenv("PASSWD_FD"))
		rc = get_password_from_file(atoi(getenv("PASSWD_FD")), NULL,
					    parsed_info);
	else if (getenv("PASSWD_FILE"))
		rc = get_password_from_file(0, getenv("PASSWD_FILE"),
					    parsed_info);

	return rc;
}

static struct option longopts[] = {
	{"all", 0, NULL, 'a'},
	{"help", 0, NULL, 'h'},
	{"move", 0, NULL, 'm'},
	{"bind", 0, NULL, 'b'},
	{"read-only", 0, NULL, 'r'},
	{"ro", 0, NULL, 'r'},
	{"verbose", 0, NULL, 'v'},
	{"version", 0, NULL, 'V'},
	{"read-write", 0, NULL, 'w'},
	{"rw", 0, NULL, 'w'},
	{"options", 1, NULL, 'o'},
	{"type", 1, NULL, 't'},
	{"uid", 1, NULL, '1'},
	{"gid", 1, NULL, '2'},
	{"user", 1, NULL, 'u'},
	{"username", 1, NULL, 'u'},
	{"dom", 1, NULL, 'd'},
	{"domain", 1, NULL, 'd'},
	{"password", 1, NULL, 'p'},
	{"pass", 1, NULL, 'p'},
	{"credentials", 1, NULL, 'c'},
	{"port", 1, NULL, 'P'},
	{NULL, 0, NULL, 0}
};

/* convert a string to uppercase. return false if the string
 * wasn't ASCII. Return success on a NULL ptr */
static int uppercase_string(char *string)
{
	if (!string)
		return 1;

	while (*string) {
		/* check for unicode */
		if ((unsigned char)string[0] & 0x80)
			return 0;
		*string = toupper((unsigned char)*string);
		string++;
	}

	return 1;
}

static void print_cifs_mount_version(void)
{
	printf("mount.cifs version: %s\n", VERSION);
}

/*
 * This function borrowed from fuse-utils...
 *
 * glibc's addmntent (at least as of 2.10 or so) doesn't properly encode
 * newlines embedded within the text fields. To make sure no one corrupts
 * the mtab, fail the mount if there are embedded newlines.
 */
static int check_newline(const char *progname, const char *name)
{
	const char *s;
	for (s = "\n"; *s; s++) {
		if (strchr(name, *s)) {
			fprintf(stderr,
				"%s: illegal character 0x%02x in mount entry\n",
				progname, *s);
			return EX_USAGE;
		}
	}
	return 0;
}

static int check_mtab(const char *progname, const char *devname,
		      const char *dir)
{
	if (check_newline(progname, devname) == -1 ||
	    check_newline(progname, dir) == -1)
		return EX_USAGE;
	return 0;
}

static int
add_mtab(char *devname, char *mountpoint, unsigned long flags)
{
	int rc = 0;
	uid_t uid;
	char *mount_user = NULL;
	struct mntent mountent;
	FILE *pmntfile;
	sigset_t mask, oldmask;

	uid = getuid();
	if (uid != 0)
		mount_user = getusername(uid);

	/*
	 * Set the real uid to the effective uid. This prevents unprivileged
	 * users from sending signals to this process, though ^c on controlling
	 * terminal should still work.
	 */
	rc = setreuid(geteuid(), -1);
	if (rc != 0) {
		fprintf(stderr, "Unable to set real uid to effective uid: %s\n",
				strerror(errno));
		return EX_FILEIO;
	}

	rc = sigfillset(&mask);
	if (rc) {
		fprintf(stderr, "Unable to set filled signal mask\n");
		return EX_FILEIO;
	}

	rc = sigprocmask(SIG_SETMASK, &mask, &oldmask);
	if (rc) {
		fprintf(stderr, "Unable to make process ignore signals\n");
		return EX_FILEIO;
	}

	rc = toggle_cap_dac_override(1);
	if (rc)
		return EX_FILEIO;

	atexit(unlock_mtab);
	rc = lock_mtab();
	if (rc) {
		fprintf(stderr, "cannot lock mtab");
		rc = EX_FILEIO;
		goto add_mtab_exit;
	}

	pmntfile = setmntent(MOUNTED, "a+");
	if (!pmntfile) {
		fprintf(stderr, "could not update mount table\n");
		unlock_mtab();
		rc = EX_FILEIO;
		goto add_mtab_exit;
	}

	mountent.mnt_fsname = devname;
	mountent.mnt_dir = mountpoint;
	mountent.mnt_type = (char *)(void *)cifs_fstype;
	mountent.mnt_opts = (char *)calloc(MTAB_OPTIONS_LEN, 1);
	if (mountent.mnt_opts) {
		if (flags & MS_RDONLY)
			strlcat(mountent.mnt_opts, "ro", MTAB_OPTIONS_LEN);
		else
			strlcat(mountent.mnt_opts, "rw", MTAB_OPTIONS_LEN);

		if (flags & MS_MANDLOCK)
			strlcat(mountent.mnt_opts, ",mand", MTAB_OPTIONS_LEN);
		if (flags & MS_NOEXEC)
			strlcat(mountent.mnt_opts, ",noexec", MTAB_OPTIONS_LEN);
		if (flags & MS_NOSUID)
			strlcat(mountent.mnt_opts, ",nosuid", MTAB_OPTIONS_LEN);
		if (flags & MS_NODEV)
			strlcat(mountent.mnt_opts, ",nodev", MTAB_OPTIONS_LEN);
		if (flags & MS_SYNCHRONOUS)
			strlcat(mountent.mnt_opts, ",sync", MTAB_OPTIONS_LEN);
		if (mount_user) {
			strlcat(mountent.mnt_opts, ",user=", MTAB_OPTIONS_LEN);
			strlcat(mountent.mnt_opts, mount_user,
				MTAB_OPTIONS_LEN);
		}
	}
	mountent.mnt_freq = 0;
	mountent.mnt_passno = 0;
	rc = addmntent(pmntfile, &mountent);
	endmntent(pmntfile);
	unlock_mtab();
	SAFE_FREE(mountent.mnt_opts);
add_mtab_exit:
	toggle_cap_dac_override(0);
	sigprocmask(SIG_SETMASK, &oldmask, NULL);
	if (rc) {
		fprintf(stderr, "unable to add mount entry to mtab\n");
		rc = EX_FILEIO;
	}

	return rc;
}

/* have the child drop root privileges */
static int
drop_child_privs(void)
{
	int rc;
	uid_t uid = getuid();
	gid_t gid = getgid();

	if (gid) {
		rc = setgid(gid);
		if (rc) {
			fprintf(stderr, "Unable set group identity: %s\n",
					strerror(errno));
			return EX_SYSERR;
		}
	}
	if (uid) {
		rc = setuid(uid);
		if (rc) {
			fprintf(stderr, "Unable set user identity: %s\n",
					strerror(errno));
			return EX_SYSERR;
		}
	}

	return 0;
}

static int
assemble_mountinfo(struct parsed_mount_info *parsed_info,
		   const char *thisprogram, const char *mountpoint,
		   const char *orig_dev, char *orgoptions)
{
	int rc;

	rc = drop_capabilities(0);
	if (rc)
		goto assemble_exit;

	rc = drop_child_privs();
	if (rc)
		goto assemble_exit;

	if (getuid()) {
		rc = check_fstab(thisprogram, mountpoint, orig_dev,
				 &orgoptions);
		if (rc)
			goto assemble_exit;

		/* enable any default user mount flags */
		parsed_info->flags |= CIFS_SETUID_FLAGS;
	}

	rc = get_pw_from_env(parsed_info);
	if (rc)
		goto assemble_exit;

	if (orgoptions) {
		rc = parse_options(orgoptions, parsed_info);
		if (rc)
			goto assemble_exit;
	}

	if (getuid()) {
		if (!(parsed_info->flags & (MS_USERS | MS_USER))) {
			fprintf(stderr, "%s: permission denied\n", thisprogram);
			rc = EX_USAGE;
			goto assemble_exit;
		}
	}

	parsed_info->flags &= ~(MS_USERS | MS_USER);

	rc = parse_unc(orig_dev, parsed_info);
	if (rc)
		goto assemble_exit;

	rc = resolve_host(parsed_info);
	if (rc)
		goto assemble_exit;

	if (!parsed_info->got_user) {
		/*
		 * Note that the password will not be retrieved from the
		 * USER env variable (ie user%password form) as there is
		 * already a PASSWD environment varaible
		 */
		if (getenv("USER"))
			strlcpy(parsed_info->username, getenv("USER"),
				sizeof(parsed_info->username));
		else
			strlcpy(parsed_info->username, getusername(getuid()),
				sizeof(parsed_info->username));
		parsed_info->got_user = 1;
	}

	if (!parsed_info->got_password) {
		/* getpass is obsolete, but there's apparently nothing that replaces it */
		char *tmp_pass = getpass("Password: ");
		if (!tmp_pass) {
			fprintf(stderr, "Error reading password, exiting\n");
			rc = EX_SYSERR;
			goto assemble_exit;
		}
		rc = set_password(parsed_info, tmp_pass);
		if (rc)
			goto assemble_exit;
	}

	/* copy in ver= string. It's not really needed, but what the hell */
	strlcat(parsed_info->options, ",ver=", sizeof(parsed_info->options));
	strlcat(parsed_info->options, OPTIONS_VERSION, sizeof(parsed_info->options));

	/* copy in user= string */
	if (parsed_info->got_user) {
		strlcat(parsed_info->options, ",user=",
			sizeof(parsed_info->options));
		strlcat(parsed_info->options, parsed_info->username,
			sizeof(parsed_info->options));
	}

	if (*parsed_info->domain) {
		strlcat(parsed_info->options, ",domain=",
			sizeof(parsed_info->options));
		strlcat(parsed_info->options, parsed_info->domain,
			sizeof(parsed_info->options));
	}

assemble_exit:
	return rc;
}

int main(int argc, char **argv)
{
	int c;
	char *orgoptions = NULL;
	char *mountpoint = NULL;
	char *options = NULL;
	char *dev_name = NULL, *orig_dev = NULL;
	char *currentaddress, *nextaddress;
	int rc = 0;
	int already_uppercased = 0;
	size_t options_size = MAX_OPTIONS_LEN;
	size_t dev_len;
	struct parsed_mount_info *parsed_info = NULL;
	pid_t pid;

	rc = check_setuid();
	if (rc)
		return rc;

	rc = drop_capabilities(1);
	if (rc)
		return EX_SYSERR;

	/* setlocale(LC_ALL, "");
	   bindtextdomain(PACKAGE, LOCALEDIR);
	   textdomain(PACKAGE); */

	if (!argc || !argv) {
		rc = mount_cifs_usage(stderr);
		goto mount_exit;
	}

	thisprogram = argv[0];
	if (thisprogram == NULL)
		thisprogram = "mount.cifs";

	/* allocate parsed_info as shared anonymous memory range */
	parsed_info = mmap(0, sizeof(*parsed_info), PROT_READ | PROT_WRITE,
			   MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (parsed_info == (struct parsed_mount_info *) -1) {
		parsed_info = NULL;
		fprintf(stderr, "Unable to allocate memory: %s\n",
				strerror(errno));
		return EX_SYSERR;
	}

	parsed_info->flags = MS_MANDLOCK;

	/* add sharename in opts string as unc= parm */
	while ((c = getopt_long(argc, argv, "?fhno:rvVw",
				longopts, NULL)) != -1) {
		switch (c) {
		case '?':
		case 'h':	/* help */
			rc = mount_cifs_usage(stdout);
			goto mount_exit;
		case 'n':
			++parsed_info->nomtab;
			break;
		case 'o':
			orgoptions = strndup(optarg, MAX_OPTIONS_LEN);
			if (!orgoptions) {
				rc = EX_SYSERR;
				goto mount_exit;
			}
			break;
		case 'r':	/* mount readonly */
			parsed_info->flags |= MS_RDONLY;
			break;
		case 'v':
			++parsed_info->verboseflag;
			break;
		case 'V':
			print_cifs_mount_version();
			exit(0);
		case 'w':
			parsed_info->flags &= ~MS_RDONLY;
			break;
		case 'f':
			++parsed_info->fakemnt;
			break;
		default:
			fprintf(stderr, "unknown command-line option: %c\n", c);
			rc = mount_cifs_usage(stderr);
			goto mount_exit;
		}
	}

	if (argc < 3 || argv[optind] == NULL || argv[optind + 1] == NULL) {
		rc = mount_cifs_usage(stderr);
		goto mount_exit;
	}

	orig_dev = argv[optind];
	mountpoint = argv[optind + 1];

	/* chdir into mountpoint as soon as possible */
	rc = chdir(mountpoint);
	if (rc) {
		fprintf(stderr, "Couldn't chdir to %s: %s\n", mountpoint,
			strerror(errno));
		rc = EX_USAGE;
		goto mount_exit;
	}

	mountpoint = realpath(".", NULL);
	if (!mountpoint) {
		fprintf(stderr, "Unable to resolve %s to canonical path: %s\n",
			mountpoint, strerror(errno));
		rc = EX_SYSERR;
		goto mount_exit;
	}

	/*
	 * mount.cifs does privilege separation. Most of the code to handle
	 * assembling the mount info is done in a child process that drops
	 * privileges. The info is assembled in parsed_info which is a
	 * shared, mmaped memory segment. The parent waits for the child to
	 * exit and checks the return code. If it's anything but "0", then
	 * the process exits without attempting anything further.
	 */
	pid = fork();
	if (pid == -1) {
		fprintf(stderr, "Unable to fork: %s\n", strerror(errno));
		rc = EX_SYSERR;
		goto mount_exit;
	} else if (!pid) {
		/* child */
		rc = assemble_mountinfo(parsed_info, thisprogram, mountpoint,
					orig_dev, orgoptions);
		return rc;
	} else {
		/* parent */
		pid = wait(&rc);
		if (!WIFEXITED(rc)) {
			fprintf(stderr, "Child process terminated abnormally.\n");
			rc = EX_SYSERR;
			goto mount_exit;
		}
		rc = WEXITSTATUS(rc);
		if (rc)
			goto mount_exit;
	}

	options = calloc(options_size, 1);
	if (!options) {
		fprintf(stderr, "Unable to allocate memory.\n");
		rc = EX_SYSERR;
		goto mount_exit;
	}

	dev_len = strnlen(parsed_info->host, sizeof(parsed_info->host)) +
	    strnlen(parsed_info->share, sizeof(parsed_info->share)) +
	    strnlen(parsed_info->prefix, sizeof(parsed_info->prefix)) +
	    2 + 1 + 1 + 1;
	dev_name = calloc(dev_len, 1);
	if (!dev_name) {
		rc = EX_SYSERR;
		goto mount_exit;
	}

	/* rebuild device name with forward slashes */
	strlcpy(dev_name, "//", dev_len);
	strlcat(dev_name, parsed_info->host, dev_len);
	strlcat(dev_name, "/", dev_len);
	strlcat(dev_name, parsed_info->share, dev_len);
	strlcat(dev_name, parsed_info->prefix, dev_len);

	currentaddress = parsed_info->addrlist;
	nextaddress = strchr(currentaddress, ',');
	if (nextaddress)
		*nextaddress++ = '\0';

mount_retry:
	if (!currentaddress) {
		fprintf(stderr, "Unable to find suitable address.\n");
		rc = EX_SYSERR;
		goto mount_exit;
	}
	strlcpy(options, "ip=", options_size);
	strlcat(options, currentaddress, options_size);

	strlcat(options, ",unc=\\\\", options_size);
	strlcat(options, parsed_info->host, options_size);
	strlcat(options, "\\", options_size);
	strlcat(options, parsed_info->share, options_size);

	if (*parsed_info->options) {
		strlcat(options, ",", options_size);
		strlcat(options, parsed_info->options, options_size);
	}

	if (*parsed_info->prefix) {
		strlcat(options, ",prefixpath=", options_size);
		strlcat(options, parsed_info->prefix, options_size);
	}

	if (parsed_info->verboseflag)
		fprintf(stderr, "mount.cifs kernel mount options: %s\n",
			options);

	if (parsed_info->got_password) {
		/*
		 * Commas have to be doubled, or else they will
		 * look like the parameter separator
		 */
		strlcat(options, ",pass=", options_size);
		strlcat(options, parsed_info->password, options_size);
		if (parsed_info->verboseflag)
			fprintf(stderr, ",pass=********");
	}

	if (parsed_info->verboseflag)
		fprintf(stderr, "\n");

	rc = check_mtab(thisprogram, dev_name, mountpoint);
	if (rc)
		goto mount_exit;

	if (!parsed_info->fakemnt
	    && mount(dev_name, ".", cifs_fstype, parsed_info->flags, options)) {
		switch (errno) {
		case ECONNREFUSED:
		case EHOSTUNREACH:
			currentaddress = nextaddress;
			nextaddress = strchr(currentaddress, ',');
			if (nextaddress)
				*nextaddress++ = '\0';
			goto mount_retry;
		case ENODEV:
			fprintf(stderr,
				"mount error: cifs filesystem not supported by the system\n");
			break;
		case ENXIO:
			if (!already_uppercased &&
			    uppercase_string(parsed_info->host) &&
			    uppercase_string(parsed_info->share) &&
			    uppercase_string(parsed_info->prefix)) {
				fprintf(stderr,
					"Retrying with upper case share name\n");
				already_uppercased = 1;
				goto mount_retry;
			}
		}
		fprintf(stderr, "mount error(%d): %s\n", errno,
			strerror(errno));
		fprintf(stderr,
			"Refer to the mount.cifs(8) manual page (e.g. man "
			"mount.cifs)\n");
		rc = EX_FAIL;
		goto mount_exit;
	}

	if (!parsed_info->nomtab)
		rc = add_mtab(dev_name, mountpoint, parsed_info->flags);

mount_exit:
	if (parsed_info) {
		memset(parsed_info->password, 0, sizeof(parsed_info->password));
		munmap(parsed_info, sizeof(*parsed_info));
	}
	SAFE_FREE(dev_name);
	SAFE_FREE(options);
	SAFE_FREE(orgoptions);
	return rc;
}
