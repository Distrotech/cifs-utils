/* 
   Mount helper utility for Linux CIFS VFS (virtual filesystem) client
   Copyright (C) 2003,2008 Steve French  (sfrench@us.ibm.com)
   Copyright (C) 2008 Jeremy Allison (jra@samba.org)

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

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

/*
 * Maximum length of "share" portion of a UNC. I have no idea if this is at
 * all valid. According to MSDN, the typical max length of any component is
 * 255, so use that here.
 */
#define MAX_SHARE_LEN 256

/* currently maximum length of IPv6 address string */
#define MAX_ADDRESS_LEN INET6_ADDRSTRLEN

/* limit list of addresses to 16 max-size addrs */
#define MAX_ADDR_LIST_LEN (MAX_ADDRESS_LEN * 16)

#ifndef SAFE_FREE
#define SAFE_FREE(x) do { if ((x) != NULL) {free(x); x=NULL;} } while(0)
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
 * because of users and distributions installing it as a setuid root program.
 * mount.cifs has not been audited for security. Thus, we strongly recommend
 * that it not be installed setuid root. To make that abundantly clear,
 * mount.cifs now check whether it's running setuid root and exit with an
 * error if it is. If you wish to disable this check, then set the following
 * #define to 1, but please realize that you do so at your own peril.
 */
#define CIFS_DISABLE_SETUID_CHECK 0

/*
 * By default, mount.cifs follows the conventions set forth by /bin/mount
 * for user mounts. That is, it requires that the mount be listed in
 * /etc/fstab with the "user" option when run as an unprivileged user and
 * mount.cifs is setuid root.
 *
 * Older versions of mount.cifs however were "looser" in this regard. When
 * made setuid root, a user could run mount.cifs directly and mount any share
 * on a directory owned by that user.
 *
 * The legacy behavior is now disabled by default. To reenable it, set the
 * following #define to true.
 */
#define CIFS_LEGACY_SETUID_CHECK 0

/*
 * When an unprivileged user runs a setuid mount.cifs, we set certain mount
 * flags by default. These defaults can be changed here.
 */
#define CIFS_SETUID_FLAGS (MS_NOSUID|MS_NODEV)

/* struct for holding parsed mount info for use by privleged process */
struct parsed_mount_info {
	unsigned long	flags;
	char		host[NI_MAXHOST];
	char		share[MAX_SHARE_LEN];
	char		prefix[PATH_MAX];
	char		options[MAX_OPTIONS_LEN];
	char		password[MOUNT_PASSWD_SIZE + 1];
	char		address_list[MAX_ADDR_LIST_LEN];
	unsigned int	got_password:1;
};

const char *thisprogram;
int verboseflag = 0;
int fakemnt = 0;
static int got_user = 0;
static int got_domain = 0;
static int got_ip = 0;
static int got_unc = 0;
static int got_uid = 0;
static int got_gid = 0;
static char * user_name = NULL;
char * domain_name = NULL;
char * prefixpath = NULL;
const char *cifs_fstype = "cifs";

#if CIFS_LEGACY_SETUID_CHECK
static int
check_mountpoint(const char *progname, char *mountpoint)
{
	/* do extra checks on mountpoint for legacy setuid behavior */
	if (!getuid() || geteuid())
		return 0;

	if (statbuf.st_uid != getuid()) {
		fprintf(stderr, "%s: %s is not owned by user\n", progname,
			mountpoint);
		return EX_USAGE;
	}

	if ((statbuf.st_mode & S_IRWXU) != S_IRWXU) {
		fprintf(stderr, "%s: invalid permissions on %s\n", progname,
			mountpoint);
		return EX_USAGE;
	}

	return 0;
}
#else /* CIFS_LEGACY_SETUID_CHECK */
static int
check_mountpoint(const char *progname, char *mountpoint)
{
	return 0;
}
#endif /* CIFS_LEGACY_SETUID_CHECK */

#if CIFS_DISABLE_SETUID_CHECK
static int
check_setuid(void)
{
	return 0;
}
#else /* CIFS_DISABLE_SETUID_CHECK */
static int
check_setuid(void)
{
	if (getuid() && !geteuid()) {
		printf("This mount.cifs program has been built with the "
			"ability to run as a setuid root program disabled.\n"
			"mount.cifs has not been well audited for security "
			"holes. Therefore the Samba team does not recommend "
			"installing it as a setuid root program.\n");
		return 1;
	}

	return 0;
}
#endif /* CIFS_DISABLE_SETUID_CHECK */

#if CIFS_LEGACY_SETUID_CHECK
static int
check_fstab(const char *progname, char *mountpoint, char *devname,
	    char **options)
{
	return 0;
}
#else /* CIFS_LEGACY_SETUID_CHECK */
static int
check_fstab(const char *progname, char *mountpoint, char *devname,
	    char **options)
{
	FILE *fstab;
	struct mntent *mnt;

	/* make sure this mount is listed in /etc/fstab */
	fstab = setmntent(_PATH_FSTAB, "r");
	if (!fstab) {
		fprintf(stderr, "Couldn't open %s for reading!\n",
				_PATH_FSTAB);
		return EX_FILEIO;
	}

	while((mnt = getmntent(fstab))) {
		if (!strcmp(mountpoint, mnt->mnt_dir))
			break;
	}
	endmntent(fstab);

	if (mnt == NULL || strcmp(mnt->mnt_fsname, devname)) {
		fprintf(stderr, "%s: permission denied: no match for "
				"%s found in %s\n", progname, mountpoint,
				_PATH_FSTAB);
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
#endif /* CIFS_LEGACY_SETUID_CHECK */

/* BB finish BB

        cifs_umount
        open nofollow - avoid symlink exposure? 
        get owner of dir see if matches self or if root
        call system(umount argv) etc.
                
BB end finish BB */

static char * check_for_domain(char **);


static int
mount_cifs_usage(FILE *stream)
{
	fprintf(stream, "\nUsage:  %s <remotetarget> <dir> -o <options>\n", thisprogram);
	fprintf(stream, "\nMount the remote target, specified as a UNC name,");
	fprintf(stream, " to a local directory.\n\nOptions:\n");
	fprintf(stream, "\tuser=<arg>\n\tpass=<arg>\n\tdom=<arg>\n");
	fprintf(stream, "\nLess commonly used options:");
	fprintf(stream, "\n\tcredentials=<filename>,guest,perm,noperm,setuids,nosetuids,rw,ro,");
	fprintf(stream, "\n\tsep=<char>,iocharset=<codepage>,suid,nosuid,exec,noexec,serverino,");
	fprintf(stream, "\n\tmapchars,nomapchars,nolock,servernetbiosname=<SRV_RFC1001NAME>");
	fprintf(stream, "\n\tdirectio,nounix,cifsacl,sec=<authentication mechanism>,sign");
	fprintf(stream, "\n\nOptions not needed for servers supporting CIFS Unix extensions");
	fprintf(stream, "\n\t(e.g. unneeded for mounts to most Samba versions):");
	fprintf(stream, "\n\tuid=<uid>,gid=<gid>,dir_mode=<mode>,file_mode=<mode>,sfu");
	fprintf(stream, "\n\nRarely used options:");
	fprintf(stream, "\n\tport=<tcpport>,rsize=<size>,wsize=<size>,unc=<unc_name>,ip=<ip_address>,");
	fprintf(stream, "\n\tdev,nodev,nouser_xattr,netbiosname=<OUR_RFC1001NAME>,hard,soft,intr,");
	fprintf(stream, "\n\tnointr,ignorecase,noposixpaths,noacl,prefixpath=<path>,nobrl");
	fprintf(stream, "\n\nOptions are described in more detail in the manual page");
	fprintf(stream, "\n\tman 8 mount.cifs\n");
	fprintf(stream, "\nTo display the version number of the mount helper:");
	fprintf(stream, "\n\t%s -V\n",thisprogram);

	if (stream == stderr)
		return EX_USAGE;
	return 0;
}

/* caller frees username if necessary */
static char * getusername(void) {
	char *username = NULL;
	struct passwd *password = getpwuid(getuid());

	if (password) {
		username = password->pw_name;
	}
	return username;
}

static int open_cred_file(char *file_name, struct parsed_mount_info *parsed_info)
{
	char * line_buf;
	char * temp_val;
	FILE * fs;
	int i, length;

	i = access(file_name, R_OK);
	if (i)
		return i;

	fs = fopen(file_name,"r");
	if(fs == NULL)
		return errno;
	line_buf = (char *)malloc(4096);
	if(line_buf == NULL) {
		fclose(fs);
		return EX_SYSERR;
	}

	while(fgets(line_buf,4096,fs)) {
		/* parse line from credential file */

		/* eat leading white space */
		for(i=0;i<4086;i++) {
			if((line_buf[i] != ' ') && (line_buf[i] != '\t'))
				break;
			/* if whitespace - skip past it */
		}
		if (strncasecmp("username",line_buf+i,8) == 0) {
			temp_val = strchr(line_buf + i,'=');
			if(temp_val) {
				/* go past equals sign */
				temp_val++;
				for(length = 0;length<4087;length++) {
					if ((temp_val[length] == '\n')
					    || (temp_val[length] == '\0')) {
						temp_val[length] = '\0';
						break;
					}
				}
				if(length > 4086) {
					fprintf(stderr, "mount.cifs failed due to malformed username in credentials file\n");
					memset(line_buf,0,4096);
					return EX_USAGE;
				} else {
					got_user = 1;
					user_name = (char *)calloc(1 + length,1);
					/* BB adding free of user_name string before exit,
						not really necessary but would be cleaner */
					strlcpy(user_name,temp_val, length+1);
				}
			}
		} else if (strncasecmp("password",line_buf+i,8) == 0) {
			temp_val = strchr(line_buf+i,'=');
			if(temp_val) {
				/* go past equals sign */
				temp_val++;
				for(length = 0;length<MOUNT_PASSWD_SIZE+1;length++) {
					if ((temp_val[length] == '\n')
					    || (temp_val[length] == '\0')) {
						temp_val[length] = '\0';
						break;
					}
				}
				if(length > MOUNT_PASSWD_SIZE) {
					fprintf(stderr, "mount.cifs failed: password in credentials file too long\n");
					memset(line_buf, 0, 4096);
					return EX_USAGE;
				}
				strlcpy(parsed_info->password, temp_val, MOUNT_PASSWD_SIZE + 1);
				parsed_info->got_password = 1;
			}
                } else if (strncasecmp("domain",line_buf+i,6) == 0) {
                        temp_val = strchr(line_buf+i,'=');
                        if(temp_val) {
                                /* go past equals sign */
                                temp_val++;
				if(verboseflag)
					fprintf(stderr, "\nDomain %s\n",temp_val);
                                for(length = 0;length<DOMAIN_SIZE+1;length++) {
					if ((temp_val[length] == '\n')
					    || (temp_val[length] == '\0')) {
						temp_val[length] = '\0';
						break;
					}
                                }
                                if(length > DOMAIN_SIZE) {
                                        fprintf(stderr, "mount.cifs failed: domain in credentials file too long\n");
                                        return EX_USAGE;
                                } else {
                                        if(domain_name == NULL) {
                                                domain_name = (char *)calloc(DOMAIN_SIZE+1,1);
                                        } else
                                                memset(domain_name,0,DOMAIN_SIZE);
                                        if(domain_name) {
                                                strlcpy(domain_name,temp_val,DOMAIN_SIZE+1);
                                                got_domain = 1;
                                        }
                                }
                        }
                }

	}
	fclose(fs);
	SAFE_FREE(line_buf);
	return 0;
}

static int
get_password_from_file(int file_descript, char *filename, struct parsed_mount_info *parsed_info)
{
	int rc = 0;
	int i;
	char c;

	if(filename != NULL) {
		rc = access(filename, R_OK);
		if (rc) {
			fprintf(stderr, "mount.cifs failed: access check of %s failed: %s\n",
					filename, strerror(errno));
			return EX_SYSERR;
		}
		file_descript = open(filename, O_RDONLY);
		if(file_descript < 0) {
			fprintf(stderr, "mount.cifs failed. %s attempting to open password file %s\n",
				   strerror(errno),filename);
			return EX_SYSERR;
		}
	}
	/* else file already open and fd provided */

	for(i=0;i<MOUNT_PASSWD_SIZE;i++) {
		rc = read(file_descript,&c,1);
		if(rc < 0) {
			fprintf(stderr, "mount.cifs failed. Error %s reading password file\n",strerror(errno));
			if(filename != NULL)
				close(file_descript);
			return EX_SYSERR;
		} else if(rc == 0) {
			if(parsed_info->password[0] == 0) {
				if(verboseflag)
					fprintf(stderr, "\nWarning: null password used since cifs password file empty");
			}
			break;
		} else /* read valid character */ {
			if((c == 0) || (c == '\n')) {
				parsed_info->password[i] = '\0';
				break;
			} else 
				parsed_info->password[i] = c;
		}
	}
	if((i == MOUNT_PASSWD_SIZE) && (verboseflag)) {
		fprintf(stderr, "\nWarning: password longer than %d characters specified in cifs password file",
			MOUNT_PASSWD_SIZE);
	}
	parsed_info->got_password = 1;
	if(filename != NULL) {
		close(file_descript);
	}

	return rc;
}

static int
parse_options(const char *data, struct parsed_mount_info *parsed_info)
{
	char *percent_char = NULL;
	char *value = NULL, *equals = NULL;
	char *next_keyword = NULL;
	char *out = parsed_info->options;
	unsigned long *filesys_flags = &parsed_info->flags;
	int out_len = 0;
	int word_len;
	int rc = 0;
	char user[32];
	char group[32];

	/* make sure we're starting from beginning */
	out[0] = '\0';

	/* BB fixme check for separator override BB */
	if (getuid()) {
		got_uid = 1;
		snprintf(user,sizeof(user),"%u",getuid());
		got_gid = 1;
		snprintf(group,sizeof(group),"%u",getgid());
	}

	if (!data)
		return EX_USAGE;

	/*
	 * format is keyword,keyword2=value2,keyword3=value3... 
	 * data  = next keyword
	 * value = next value ie stuff after equal sign
	 */
	while (data && *data) {
		next_keyword = strchr(data,','); /* BB handle sep= */
	
		/* temporarily null terminate end of keyword=value pair */
		if(next_keyword)
			*next_keyword++ = 0;

		/* temporarily null terminate keyword if there's a value */
		value = NULL;
		if ((equals = strchr(data, '=')) != NULL) {
			*equals = '\0';
			value = equals + 1;
		}

		/* FIXME: turn into a token parser? */
		if (strncmp(data, "users",5) == 0) {
			if(!value || !*value) {
				*filesys_flags |= MS_USERS;
				goto nocopy;
			}
		} else if (strncmp(data, "user_xattr",10) == 0) {
		   /* do nothing - need to skip so not parsed as user name */
		} else if (strncmp(data, "user", 4) == 0) {

			if (!value || !*value) {
				if(data[4] == '\0') {
					*filesys_flags |= MS_USER;
					goto nocopy;
				} else {
					fprintf(stderr, "username specified with no parameter\n");
					return EX_USAGE;
				}
			} else {
				if (strnlen(value, 260) < 260) {
					got_user=1;
					percent_char = strchr(value,'%');
					if(percent_char) {
						*percent_char = ',';
						if(parsed_info->got_password)
							fprintf(stderr, "\nmount.cifs warning - password specified twice\n");
						parsed_info->got_password = 1;
						percent_char++;
						strlcpy(parsed_info->password, percent_char, sizeof(parsed_info->password));
						/*  remove password from username */
						while(*percent_char != 0) {
							*percent_char = ',';
							percent_char++;
						}
					}
					/* this is only case in which the user
					name buf is not malloc - so we have to
					check for domain name embedded within
					the user name here since the later
					call to check_for_domain will not be
					invoked */
					domain_name = check_for_domain(&value);
				} else {
					fprintf(stderr, "username too long\n");
					return EX_USAGE;
				}
			}
		} else if (strncmp(data, "pass", 4) == 0) {
			if (!value || !*value) {
				if(parsed_info->got_password) {
					fprintf(stderr, "\npassword specified twice, ignoring second\n");
				} else
					parsed_info->got_password = 1;
			} else if (strnlen(value, MOUNT_PASSWD_SIZE) < MOUNT_PASSWD_SIZE) {
				if (parsed_info->got_password) {
					fprintf(stderr, "\nmount.cifs warning - password specified twice\n");
				} else {
					strlcpy(parsed_info->password, value, MOUNT_PASSWD_SIZE + 1);
					parsed_info->got_password = 1;
				}
			} else {
				fprintf(stderr, "password too long\n");
				return EX_USAGE;
			}
			goto nocopy;
		} else if (strncmp(data, "sec", 3) == 0) {
			if (value) {
				if (!strncmp(value, "none", 4) ||
				    !strncmp(value, "krb5", 4))
					parsed_info->got_password = 1;
			}
		} else if (strncmp(data, "ip", 2) == 0) {
			if (!value || !*value) {
				fprintf(stderr, "target ip address argument missing");
			} else if (strnlen(value, MAX_ADDRESS_LEN) <= MAX_ADDRESS_LEN) {
				if(verboseflag)
					fprintf(stderr, "ip address %s override specified\n",value);
				got_ip = 1;
			} else {
				fprintf(stderr, "ip address too long\n");
				return EX_USAGE;
			}
		} else if ((strncmp(data, "unc", 3) == 0)
		   || (strncmp(data, "target", 6) == 0)
		   || (strncmp(data, "path", 4) == 0)) {
			if (!value || !*value) {
				fprintf(stderr, "invalid path to network resource\n");
				return EX_USAGE;  /* needs_arg; */
			} else if(strnlen(value,5) < 5) {
				fprintf(stderr, "UNC name too short");
			}

			if (strnlen(value, 300) < 300) {
				got_unc = 1;
				if (strncmp(value, "//", 2) == 0) {
					if(got_unc)
						fprintf(stderr, "unc name specified twice, ignoring second\n");
					else
						got_unc = 1;
				} else if (strncmp(value, "\\\\", 2) != 0) {	                   
					fprintf(stderr, "UNC Path does not begin with // or \\\\ \n");
					return EX_USAGE;
				} else {
					if(got_unc)
						fprintf(stderr, "unc name specified twice, ignoring second\n");
					else
						got_unc = 1;
				}
			} else {
				fprintf(stderr, "CIFS: UNC name too long\n");
				return EX_USAGE;
			}
		} else if ((strncmp(data, "dom" /* domain */, 3) == 0)
			   || (strncmp(data, "workg", 5) == 0)) {
			/* note this allows for synonyms of "domain"
			   such as "DOM" and "dom" and "workgroup"
			   and "WORKGRP" etc. */
			if (!value || !*value) {
				fprintf(stderr, "CIFS: invalid domain name\n");
				return EX_USAGE;
			}
			if (strnlen(value, DOMAIN_SIZE+1) < DOMAIN_SIZE+1) {
				got_domain = 1;
			} else {
				fprintf(stderr, "domain name too long\n");
				return EX_USAGE;
			}
		} else if (strncmp(data, "cred", 4) == 0) {
			if (value && *value) {
				rc = open_cred_file(value, parsed_info);
				if (rc) {
					fprintf(stderr, "error %d (%s) opening credential file %s\n",
						rc, strerror(rc), value);
					return rc;
				}
			} else {
				fprintf(stderr, "invalid credential file name specified\n");
				return EX_USAGE;
			}
		} else if (strncmp(data, "uid", 3) == 0) {
			if (value && *value) {
				got_uid = 1;
				if (!isdigit(*value)) {
					struct passwd *pw;

					if (!(pw = getpwnam(value))) {
						fprintf(stderr, "bad user name \"%s\"\n", value);
						return EX_USAGE;
					}
					snprintf(user, sizeof(user), "%u", pw->pw_uid);
				} else {
					strlcpy(user,value,sizeof(user));
				}
			}
			goto nocopy;
		} else if (strncmp(data, "gid", 3) == 0) {
			if (value && *value) {
				got_gid = 1;
				if (!isdigit(*value)) {
					struct group *gr;

					if (!(gr = getgrnam(value))) {
						fprintf(stderr, "bad group name \"%s\"\n", value);
						return EX_USAGE;
					}
					snprintf(group, sizeof(group), "%u", gr->gr_gid);
				} else {
					strlcpy(group,value,sizeof(group));
				}
			}
			goto nocopy;
       /* fmask and dmask synonyms for people used to smbfs syntax */
		} else if (strcmp(data, "file_mode") == 0 || strcmp(data, "fmask")==0) {
			if (!value || !*value) {
				fprintf(stderr, "Option '%s' requires a numerical argument\n", data);
				return EX_USAGE;
			}

			if (value[0] != '0') {
				fprintf(stderr, "WARNING: '%s' not expressed in octal.\n", data);
			}

			if (strcmp (data, "fmask") == 0) {
				fprintf(stderr, "WARNING: CIFS mount option 'fmask' is deprecated. Use 'file_mode' instead.\n");
				data = "file_mode"; /* BB fix this */
			}
		} else if (strcmp(data, "dir_mode") == 0 || strcmp(data, "dmask")==0) {
			if (!value || !*value) {
				fprintf(stderr, "Option '%s' requires a numerical argument\n", data);
				return EX_USAGE;
			}

			if (value[0] != '0') {
				fprintf(stderr, "WARNING: '%s' not expressed in octal.\n", data);
			}

			if (strcmp (data, "dmask") == 0) {
				fprintf(stderr, "WARNING: CIFS mount option 'dmask' is deprecated. Use 'dir_mode' instead.\n");
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
			user_name = (char *)calloc(1, 1);
			got_user = 1;
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

/* replace all (one or more) commas with double commas */
static int
replace_commas(char *pass)
{
	/* a little extra buffer to simplify conversion */
	char tmpbuf[MOUNT_PASSWD_SIZE + 3];
	int i = 0, j = 0;

	/* don't do anything if there are no commas */
	if (!strchr(pass, ','))
		return 0;

	while (pass[i]) {
		if (pass[i] == ',')
			tmpbuf[j++] = ',';
		tmpbuf[j++] = pass[i++];
		if (j > MOUNT_PASSWD_SIZE + 1) {
			fprintf(stderr, "Converted password too long!\n");
			return EX_USAGE;
		}
	}
	tmpbuf[j] = '\0';
	strlcpy(pass, tmpbuf, MOUNT_PASSWD_SIZE + 1);
	return 0;
}

/* Usernames can not have backslash in them and we use
   [BB check if usernames can have forward slash in them BB] 
   backslash as domain\user separator character
*/
static char * check_for_domain(char **ppuser)
{
	char * original_string;
	char * usernm;
	char * domainnm;
	int    original_len;
	int    len;
	int    i;

	if(ppuser == NULL)
		return NULL;

	original_string = *ppuser;

	if (original_string == NULL)
		return NULL;
	
	original_len = strlen(original_string);

	usernm = strchr(*ppuser,'/');
	if (usernm == NULL) {
		usernm = strchr(*ppuser,'\\');
		if (usernm == NULL)
			return NULL;
	}

	if(got_domain) {
		fprintf(stderr, "Domain name specified twice. Username probably malformed\n");
		return NULL;
	}

	usernm[0] = 0;
	domainnm = *ppuser;
	if (domainnm[0] != 0) {
		got_domain = 1;
	} else {
		fprintf(stderr, "null domain\n");
	}
	len = strlen(domainnm);
	/* reset domainm to new buffer, and copy
	domain name into it */
	domainnm = (char *)malloc(len+1);
	if(domainnm == NULL)
		return NULL;

	strlcpy(domainnm,*ppuser,len+1);

/*	move_string(*ppuser, usernm+1) */
	len = strlen(usernm+1);

	if(len >= original_len) {
		/* should not happen */
		return domainnm;
	}

	for(i=0;i<original_len;i++) {
		if(i<len)
			original_string[i] = usernm[i+1];
		else /* stuff with commas to remove last parm */
			original_string[i] = ',';
	}

	/* BB add check for more than one slash? 
	  strchr(*ppuser,'/');
	  strchr(*ppuser,'\\') 
	*/
	
	return domainnm;
}

/* replace all occurances of "from" in a string with "to" */
static void replace_char(char *string, char from, char to, int maxlen)
{
	char *lastchar = string + maxlen;
	while (string) {
		string = strchr(string, from);
		if (string) {
			*string = to;
			if (string >= lastchar)
				return;
		}
	}
}

/* Note that caller frees the returned buffer if necessary */
static struct addrinfo *
parse_server(char **punc_name)
{
	char *unc_name = *punc_name;
	int length = strnlen(unc_name, MAX_UNC_LEN);
	char *share;
	struct addrinfo *addrlist;
	int rc;

	if(length > (MAX_UNC_LEN - 1)) {
		fprintf(stderr, "mount error: UNC name too long\n");
		return NULL;
	}

	if(length < 3) {
		fprintf(stderr, "mount error: UNC name too short\n");
		return NULL;
	}

	if ((strncasecmp("cifs://", unc_name, 7) == 0) ||
	    (strncasecmp("smb://", unc_name, 6) == 0)) {
		fprintf(stderr, "Mounting cifs URL not implemented yet. Attempt to mount %s\n", unc_name);
		return NULL;
	}

	if(strncmp(unc_name,"//",2) && strncmp(unc_name,"\\\\",2)) {
		/* check for nfs syntax ie server:share */
		share = strchr(unc_name,':');
		if(!share) {
			fprintf(stderr, "mount error: improperly formatted UNC name.");
			fprintf(stderr, " %s does not begin with \\\\ or //\n",unc_name);
			return NULL;
		}

		*punc_name = (char *)malloc(length + 3);
		if(*punc_name == NULL) {
			*punc_name = unc_name;
			return NULL;
		}

		*share = '/';
		strlcpy((*punc_name)+2, unc_name, length + 1);
		SAFE_FREE(unc_name);
		unc_name = *punc_name;
		unc_name[length+2] = 0;
	}

	unc_name[0] = '/';
	unc_name[1] = '/';
	unc_name += 2;

	/*
	 * allow for either delimiter between host and sharename
	 * If there's not one, then the UNC is malformed
	 */
	if (!(share = strpbrk(unc_name, "/\\"))) {
		fprintf(stderr, "mount error: Malformed UNC\n");
		return NULL;
	}

	*share = 0;  /* temporarily terminate the string */
	share += 1;
	if(got_ip == 0) {
		rc = getaddrinfo(unc_name, NULL, NULL, &addrlist);
		if (rc != 0) {
			fprintf(stderr, "mount error: could not resolve address for %s: %s\n",
				unc_name, gai_strerror(rc));
			addrlist = NULL;
		}
	}
	*(share - 1) = '/'; /* put delimiter back */

	/* we don't convert the prefixpath delimiters since '\\' is a valid char in posix paths */
	if ((prefixpath = strpbrk(share, "/\\"))) {
		*prefixpath = 0;  /* permanently terminate the string */
		if (!strlen(++prefixpath))
			prefixpath = NULL; /* this needs to be done explicitly */
	}
	if(got_ip) {
		if(verboseflag)
			fprintf(stderr, "ip address specified explicitly\n");
		return NULL;
	}
	/* BB should we pass an alternate version of the share name as Unicode */

	return addrlist;
}

static int
get_pw_from_env(struct parsed_mount_info *parsed_info)
{
	int rc = 0;

	if (getenv("PASSWD")) {
		strlcpy(parsed_info->password, getenv("PASSWD"), MOUNT_PASSWD_SIZE + 1);
		parsed_info->got_password = 1;
	} else if (getenv("PASSWD_FD"))
		rc = get_password_from_file(atoi(getenv("PASSWD_FD")), NULL, parsed_info);
	else if (getenv("PASSWD_FILE"))
		rc = get_password_from_file(0, getenv("PASSWD_FILE"), parsed_info);

	return rc;
}

static struct option longopts[] = {
	{ "all", 0, NULL, 'a' },
	{ "help",0, NULL, 'h' },
	{ "move",0, NULL, 'm' },
	{ "bind",0, NULL, 'b' },
	{ "read-only", 0, NULL, 'r' },
	{ "ro", 0, NULL, 'r' },
	{ "verbose", 0, NULL, 'v' },
	{ "version", 0, NULL, 'V' },
	{ "read-write", 0, NULL, 'w' },
	{ "rw", 0, NULL, 'w' },
	{ "options", 1, NULL, 'o' },
	{ "type", 1, NULL, 't' },
	{ "uid", 1, NULL, '1'},
	{ "gid", 1, NULL, '2'},
	{ "user",1,NULL,'u'},
	{ "username",1,NULL,'u'},
	{ "dom",1,NULL,'d'},
	{ "domain",1,NULL,'d'},
	{ "password",1,NULL,'p'},
	{ "pass",1,NULL,'p'},
	{ "credentials",1,NULL,'c'},
	{ "port",1,NULL,'P'},
	{ NULL, 0, NULL, 0 }
};

/* convert a string to uppercase. return false if the string
 * wasn't ASCII. Return success on a NULL ptr */
static int
uppercase_string(char *string)
{
	if (!string)
		return 1;

	while (*string) {
		/* check for unicode */
		if ((unsigned char) string[0] & 0x80)
			return 0;
		*string = toupper((unsigned char) *string);
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
            fprintf(stderr, "%s: illegal character 0x%02x in mount entry\n",
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


int main(int argc, char ** argv)
{
	int c;
	char * orgoptions = NULL;
	char * share_name = NULL;
	const char * ipaddr = NULL;
	char * mountpoint = NULL;
	char * options = NULL;
	char * optionstail;
	char * resolved_path = NULL;
	char * temp;
	char * dev_name = NULL;
	int rc = 0;
	int nomtab = 0;
	int uid = 0;
	int gid = 0;
	size_t options_size = MAX_OPTIONS_LEN;
	size_t current_len;
	int retry = 0; /* set when we have to retry mount with uppercase */
	struct addrinfo *addrhead = NULL, *addr;
	struct mntent mountent;
	struct sockaddr_in *addr4 = NULL;
	struct sockaddr_in6 *addr6 = NULL;
	struct parsed_mount_info *parsed_info = NULL;
	FILE * pmntfile;

	if (check_setuid())
		return EX_USAGE;

	/* setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE); */

	if (!argc || !argv) {
		rc = mount_cifs_usage(stderr);
		goto mount_exit;
	}

	thisprogram = argv[0];
	if(thisprogram == NULL)
		thisprogram = "mount.cifs";

	parsed_info = calloc(1, sizeof(*parsed_info));
	if (!parsed_info) {
		fprintf(stderr, "Unable to allocate memory.\n");
		return EX_SYSERR;
	}

	parsed_info->flags = MS_MANDLOCK;

	/* add sharename in opts string as unc= parm */
	while ((c = getopt_long (argc, argv, "afFhilL:no:O:rsSU:vVwt:",
			 longopts, NULL)) != -1) {
		switch (c) {
/* No code to do the following  options yet */
/*	case 'l':
		list_with_volumelabel = 1;
		break;
	case 'L':
		volumelabel = optarg;
		break; */
/*	case 'a':	       
		++mount_all;
		break; */

		case '?':
		case 'h':	 /* help */
			rc = mount_cifs_usage(stdout);
			goto mount_exit;
		case 'n':
			++nomtab;
			break;
		case 'b':
#ifdef MS_BIND
			parsed_info->flags |= MS_BIND;
#else
			fprintf(stderr,
				"option 'b' (MS_BIND) not supported\n");
#endif
			break;
		case 'm':
#ifdef MS_MOVE		      
			parsed_info->flags |= MS_MOVE;
#else
			fprintf(stderr,
				"option 'm' (MS_MOVE) not supported\n");
#endif
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
			++verboseflag;
			break;
		case 'V':
			print_cifs_mount_version();
			exit (0);
		case 'w':
			parsed_info->flags &= ~MS_RDONLY;
			break;
		case '1':
			if (isdigit(*optarg)) {
				char *ep;

				uid = strtoul(optarg, &ep, 10);
				if (*ep) {
					fprintf(stderr, "bad uid value \"%s\"\n", optarg);
					rc = EX_USAGE;
					goto mount_exit;
				}
			} else {
				struct passwd *pw;

				if (!(pw = getpwnam(optarg))) {
					fprintf(stderr, "bad user name \"%s\"\n", optarg);
					rc = EX_USAGE;
					goto mount_exit;
				}
				uid = pw->pw_uid;
				endpwent();
			}
			break;
		case '2':
			if (isdigit(*optarg)) {
				char *ep;

				gid = strtoul(optarg, &ep, 10);
				if (*ep) {
					fprintf(stderr, "bad gid value \"%s\"\n", optarg);
					rc = EX_USAGE;
					goto mount_exit;
				}
			} else {
				struct group *gr;

				if (!(gr = getgrnam(optarg))) {
					fprintf(stderr, "bad user name \"%s\"\n", optarg);
					rc = EX_USAGE;
					goto mount_exit;
				}
				gid = gr->gr_gid;
				endpwent();
			}
			break;
		case 'u':
			got_user = 1;
			user_name = optarg;
			break;
		case 'd':
			domain_name = optarg; /* BB fix this - currently ignored */
			got_domain = 1;
			break;
		case 'p':
			strlcpy(parsed_info->password, optarg, sizeof(parsed_info->password));
			parsed_info->got_password = 1;
			break;
		case 'S':
			rc = get_password_from_file(0, NULL, parsed_info);
			if (rc)
				goto mount_exit;
			break;
		case 't':
			break;
		case 'f':
			++fakemnt;
			break;
		default:
			fprintf(stderr, "unknown mount option %c\n",c);
			rc = mount_cifs_usage(stderr);
			goto mount_exit;
		}
	}

	if(argc < 3 || argv[optind] == NULL || argv[optind + 1] == NULL) {
		rc = mount_cifs_usage(stderr);
		goto mount_exit;
	}

	dev_name = argv[optind];
	share_name = strndup(argv[optind], MAX_UNC_LEN);
	if (share_name == NULL) {
		fprintf(stderr, "%s: %s", thisprogram, strerror(ENOMEM));
		rc = EX_SYSERR;
		goto mount_exit;
	}
	mountpoint = argv[optind + 1];

	/* make sure mountpoint is legit */
	rc = chdir(mountpoint);
	if (rc) {
		fprintf(stderr, "Couldn't chdir to %s: %s\n", mountpoint,
				strerror(errno));
		rc = EX_USAGE;
		goto mount_exit;
	}

	rc = check_mountpoint(thisprogram, mountpoint);
	if (rc)
		goto mount_exit;

	/* sanity check for unprivileged mounts */
	if (getuid()) {
		rc = check_fstab(thisprogram, mountpoint, dev_name,
				 &orgoptions);
		if (rc)
			goto mount_exit;

		/* enable any default user mount flags */
		parsed_info->flags |= CIFS_SETUID_FLAGS;
	}

	rc = get_pw_from_env(parsed_info);
	if (rc)
		goto mount_exit;

	options = calloc(options_size, 1);
	if (!options) {
		fprintf(stderr, "Unable to allocate memory.\n");
		rc = EX_SYSERR;
		goto mount_exit;
	}

        if (orgoptions) {
		rc = parse_options(orgoptions, parsed_info);
		if (rc)
			goto mount_exit;
	}

	if (getuid()) {
#if !CIFS_LEGACY_SETUID_CHECK
		if (!(parsed_info->flags & (MS_USERS|MS_USER))) {
			fprintf(stderr, "%s: permission denied\n", thisprogram);
			rc = EX_USAGE;
			goto mount_exit;
		}
#endif /* !CIFS_LEGACY_SETUID_CHECK */
		
		if (geteuid()) {
			fprintf(stderr, "%s: not installed setuid - \"user\" "
					"CIFS mounts not supported.",
					thisprogram);
			rc = EX_FAIL;
			goto mount_exit;
		}
	}

	parsed_info->flags &= ~(MS_USERS|MS_USER);

	addrhead = addr = parse_server(&share_name);
	if((addrhead == NULL) && (got_ip == 0)) {
		fprintf(stderr, "No ip address specified and hostname not found\n");
		rc = EX_USAGE;
		goto mount_exit;
	}
	
	/* BB save off path and pop after mount returns? */
	resolved_path = (char *)malloc(PATH_MAX+1);
	if (!resolved_path) {
		fprintf(stderr, "Unable to allocate memory.\n");
		rc = EX_SYSERR;
		goto mount_exit;
	}

	/* Note that if we can not canonicalize the name, we get
	   another chance to see if it is valid when we chdir to it */
	if(!realpath(".", resolved_path)) {
		fprintf(stderr, "Unable to resolve %s to canonical path: %s\n",
				mountpoint, strerror(errno));
		rc = EX_SYSERR;
		goto mount_exit;
	}

	mountpoint = resolved_path; 

	if(got_user == 0) {
		/* Note that the password will not be retrieved from the
		   USER env variable (ie user%password form) as there is
		   already a PASSWD environment varaible */
		if (getenv("USER"))
			user_name = strdup(getenv("USER"));
		if (user_name == NULL)
			user_name = getusername();
		got_user = 1;
	}
       
	if(!parsed_info->got_password) {
		char *tmp_pass = getpass("Password: "); /* BB obsolete sys call but
							   no good replacement yet. */
		if (!tmp_pass) {
			fprintf(stderr, "Password not entered, exiting\n");
			rc = EX_USAGE;
			goto mount_exit;
		}
		strlcpy(parsed_info->password, tmp_pass, sizeof(parsed_info->password));
		parsed_info->got_password = 1;
	}

	if(!share_name) {
		fprintf(stderr, "No server share name specified\n");
                rc = EX_USAGE;
		goto mount_exit;
	}

mount_retry:
	if (*options)
		strlcat(options, ",", options_size);

	strlcat(options, "unc=", options_size);
	strlcat(options, share_name, options_size);

	/* scan backwards and reverse direction of slash */
	temp = strrchr(options, '/');
	if(temp > options + 6)
		*temp = '\\';
	if(user_name) {
		/* check for syntax like user=domain\user */
		if(got_domain == 0)
			domain_name = check_for_domain(&user_name);
		strlcat(options,",user=",options_size);
		strlcat(options,user_name,options_size);
	}
	if(retry == 0) {
		if(domain_name) {
			/* extra length accounted for in option string above */
			strlcat(options,",domain=",options_size);
			strlcat(options,domain_name,options_size);
		}
	}

	strlcat(options,",ver=",options_size);
	strlcat(options,OPTIONS_VERSION,options_size);

	if (*parsed_info->options) {
		strlcat(options, ",", options_size);
		strlcat(options, parsed_info->options, options_size);
	}

	if(prefixpath) {
		strlcat(options,",prefixpath=",options_size);
		strlcat(options,prefixpath,options_size); /* no need to cat the / */
	}

	/* convert all '\\' to '/' in share portion so that /proc/mounts looks pretty */
	replace_char(dev_name, '\\', '/', strlen(share_name));

	if (!got_ip && addr) {
		strlcat(options, ",ip=", options_size);
		current_len = strnlen(options, options_size);
		optionstail = options + current_len;
		switch (addr->ai_addr->sa_family) {
		case AF_INET6:
			addr6 = (struct sockaddr_in6 *) addr->ai_addr;
			ipaddr = inet_ntop(AF_INET6, &addr6->sin6_addr, optionstail,
					   options_size - current_len);
			break;
		case AF_INET:
			addr4 = (struct sockaddr_in *) addr->ai_addr;
			ipaddr = inet_ntop(AF_INET, &addr4->sin_addr, optionstail,
					   options_size - current_len);
			break;
		default:
			ipaddr = NULL;
		}

		/* if the address looks bogus, try the next one */
		if (!ipaddr) {
			addr = addr->ai_next;
			if (addr)
				goto mount_retry;
			rc = EX_SYSERR;
			goto mount_exit;
		}
	}

	if (addr && addr->ai_addr->sa_family == AF_INET6 && addr6->sin6_scope_id) {
		strlcat(options, "%", options_size);
		current_len = strnlen(options, options_size);
		optionstail = options + current_len;
		snprintf(optionstail, options_size - current_len, "%u",
			 addr6->sin6_scope_id);
	}

	if(verboseflag)
		fprintf(stderr, "\nmount.cifs kernel mount options: %s", options);

	if (parsed_info->got_password) {
		/*
		 * Commas have to be doubled, or else they will
		 * look like the parameter separator
		 */
		if(retry == 0)
			replace_commas(parsed_info->password);
		strlcat(options, ",pass=", options_size);
		strlcat(options, parsed_info->password, options_size);
		if (verboseflag)
			fprintf(stderr, ",pass=********");
	}

	if (verboseflag)
		fprintf(stderr, "\n");

	rc = check_mtab(thisprogram, dev_name, mountpoint);
	if (rc)
		goto mount_exit;

	if (!fakemnt && mount(dev_name, ".", cifs_fstype, parsed_info->flags, options)) {
		switch (errno) {
		case ECONNREFUSED:
		case EHOSTUNREACH:
			if (addr) {
				addr = addr->ai_next;
				if (addr)
					goto mount_retry;
			}
			break;
		case ENODEV:
			fprintf(stderr, "mount error: cifs filesystem not supported by the system\n");
			break;
		case ENXIO:
			if(retry == 0) {
				retry = 1;
				if (uppercase_string(dev_name) &&
				    uppercase_string(share_name) &&
				    uppercase_string(prefixpath)) {
					fprintf(stderr, "retrying with upper case share name\n");
					goto mount_retry;
				}
			}
		}
		fprintf(stderr, "mount error(%d): %s\n", errno, strerror(errno));
		fprintf(stderr, "Refer to the mount.cifs(8) manual page (e.g. man "
		       "mount.cifs)\n");
		rc = EX_FAIL;
		goto mount_exit;
	}

	if (nomtab)
		goto mount_exit;
	atexit(unlock_mtab);
	rc = lock_mtab();
	if (rc) {
		fprintf(stderr, "cannot lock mtab");
		goto mount_exit;
	}
	pmntfile = setmntent(MOUNTED, "a+");
	if (!pmntfile) {
		fprintf(stderr, "could not update mount table\n");
		unlock_mtab();
		rc = EX_FILEIO;
		goto mount_exit;
	}
	mountent.mnt_fsname = dev_name;
	mountent.mnt_dir = mountpoint;
	mountent.mnt_type = (char *)(void *)cifs_fstype;
	mountent.mnt_opts = (char *)malloc(220);
	if(mountent.mnt_opts) {
		char * mount_user = getusername();
		memset(mountent.mnt_opts,0,200);
		if(parsed_info->flags & MS_RDONLY)
			strlcat(mountent.mnt_opts,"ro",220);
		else
			strlcat(mountent.mnt_opts,"rw",220);
		if(parsed_info->flags & MS_MANDLOCK)
			strlcat(mountent.mnt_opts,",mand",220);
		if(parsed_info->flags & MS_NOEXEC)
			strlcat(mountent.mnt_opts,",noexec",220);
		if(parsed_info->flags & MS_NOSUID)
			strlcat(mountent.mnt_opts,",nosuid",220);
		if(parsed_info->flags & MS_NODEV)
			strlcat(mountent.mnt_opts,",nodev",220);
		if(parsed_info->flags & MS_SYNCHRONOUS)
			strlcat(mountent.mnt_opts,",sync",220);
		if(mount_user) {
			if(getuid() != 0) {
				strlcat(mountent.mnt_opts,
					",user=", 220);
				strlcat(mountent.mnt_opts,
					mount_user, 220);
			}
		}
	}
	mountent.mnt_freq = 0;
	mountent.mnt_passno = 0;
	rc = addmntent(pmntfile,&mountent);
	endmntent(pmntfile);
	unlock_mtab();
	SAFE_FREE(mountent.mnt_opts);
	if (rc)
		rc = EX_FILEIO;
mount_exit:
	if (addrhead)
		freeaddrinfo(addrhead);
	memset(parsed_info->password, 0, sizeof(parsed_info->password));
	SAFE_FREE(parsed_info);
	SAFE_FREE(options);
	SAFE_FREE(orgoptions);
	SAFE_FREE(resolved_path);
	SAFE_FREE(share_name);
	return rc;
}
