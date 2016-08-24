/*
* CIFS user-space helper.
* Copyright (C) Igor Mammedov (niallain@gmail.com) 2007
* Copyright (C) Jeff Layton (jlayton@samba.org) 2010
*
* Used by /sbin/request-key for handling
* cifs upcall for kerberos authorization of access to share and
* cifs upcall for DFS srver name resolving (IPv4/IPv6 aware).
* You should have keyutils installed and add something like the
* following lines to /etc/request-key.conf file:

    create cifs.spnego * * /usr/local/sbin/cifs.upcall %k
    create dns_resolver * * /usr/local/sbin/cifs.upcall %k

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
#ifdef HAVE_KRB5_KRB5_H
#include <krb5/krb5.h>
#elif defined(HAVE_KRB5_H)
#include <krb5.h>
#endif
#include <syslog.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <keyutils.h>
#include <time.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <ctype.h>

#include "replace.h"
#include "data_blob.h"
#include "spnego.h"
#include "cifs_spnego.h"

static krb5_context	context;
static const char	*prog = "cifs.upcall";

typedef enum _sectype {
	NONE = 0,
	KRB5,
	MS_KRB5
} sectype_t;

/*
 * smb_krb5_principal_get_realm
 *
 * @brief Get realm of a principal
 *
 * @param[in] context		The krb5_context
 * @param[in] principal		The principal
 * @return pointer to the realm
 *
 */
static char *cifs_krb5_principal_get_realm(krb5_principal principal)
{
#ifdef HAVE_KRB5_PRINCIPAL_GET_REALM	/* Heimdal */
	return krb5_principal_get_realm(context, principal);
#elif defined(krb5_princ_realm)	/* MIT */
	krb5_data *realm;
	realm = krb5_princ_realm(context, principal);
	return (char *)realm->data;
#else
	return NULL;
#endif
}

#if !defined(HAVE_KRB5_FREE_UNPARSED_NAME)
static void krb5_free_unparsed_name(krb5_context context, char *val)
{
	SAFE_FREE(val);
}
#endif

#if !defined(HAVE_KRB5_AUTH_CON_GETSENDSUBKEY)	/* Heimdal */
static krb5_error_code
krb5_auth_con_getsendsubkey(krb5_context context,
			    krb5_auth_context auth_context,
			    krb5_keyblock **keyblock)
{
	return krb5_auth_con_getlocalsubkey(context, auth_context, keyblock);
}
#endif

/* does the ccache have a valid TGT? */
static time_t get_tgt_time(krb5_ccache ccache)
{
	krb5_cc_cursor cur;
	krb5_creds creds;
	krb5_principal principal;
	time_t credtime = 0;
	char *realm = NULL;

	if (krb5_cc_set_flags(context, ccache, 0)) {
		syslog(LOG_DEBUG, "%s: unable to set flags", __func__);
		goto err_cache;
	}

	if (krb5_cc_get_principal(context, ccache, &principal)) {
		syslog(LOG_DEBUG, "%s: unable to get principal", __func__);
		goto err_cache;
	}

	if (krb5_cc_start_seq_get(context, ccache, &cur)) {
		syslog(LOG_DEBUG, "%s: unable to seq start", __func__);
		goto err_ccstart;
	}

	if ((realm = cifs_krb5_principal_get_realm(principal)) == NULL) {
		syslog(LOG_DEBUG, "%s: unable to get realm", __func__);
		goto err_ccstart;
	}

	while (!credtime && !krb5_cc_next_cred(context, ccache, &cur, &creds)) {
		char *name;
		if (krb5_unparse_name(context, creds.server, &name)) {
			syslog(LOG_DEBUG, "%s: unable to unparse name",
			       __func__);
			goto err_endseq;
		}
		if (krb5_realm_compare(context, creds.server, principal) &&
		    !strncasecmp(name, KRB5_TGS_NAME, KRB5_TGS_NAME_SIZE) &&
		    !strncasecmp(name + KRB5_TGS_NAME_SIZE + 1, realm,
				 strlen(realm))
		    && creds.times.endtime > time(NULL))
			credtime = creds.times.endtime;
		krb5_free_cred_contents(context, &creds);
		krb5_free_unparsed_name(context, name);
	}
err_endseq:
	krb5_cc_end_seq_get(context, ccache, &cur);
err_ccstart:
	krb5_free_principal(context, principal);
err_cache:
	return credtime;
}

static krb5_ccache
get_default_cc(void)
{
	krb5_error_code ret;
	krb5_ccache cc;

	ret = krb5_cc_default(context, &cc);
	if (ret) {
		syslog(LOG_DEBUG, "%s: krb5_cc_default returned %d", __func__, ret);
		return NULL;
	}

	if (!get_tgt_time(cc)) {
		krb5_cc_close(context, cc);
		cc = NULL;
	}
	return cc;
}


static krb5_ccache
init_cc_from_keytab(const char *keytab_name, const char *user)
{
	krb5_error_code ret;
	krb5_creds my_creds;
	krb5_keytab keytab = NULL;
	krb5_principal me = NULL;
	krb5_ccache cc = NULL;

	memset((char *) &my_creds, 0, sizeof(my_creds));

	if (keytab_name)
		ret = krb5_kt_resolve(context, keytab_name, &keytab);
	else
		ret = krb5_kt_default(context, &keytab);

	if (ret) {
		syslog(LOG_DEBUG, "%s: %d",
			keytab_name ? "krb5_kt_resolve" : "krb5_kt_default",
			(int)ret);
		goto icfk_cleanup;
	}

	ret = krb5_parse_name(context, user, &me);
	if (ret) {
		syslog(LOG_DEBUG, "krb5_parse_name: %d", (int)ret);
		goto icfk_cleanup;
	}

	ret = krb5_get_init_creds_keytab(context, &my_creds, me,
			keytab, 0, NULL, NULL);
	if (ret) {
		syslog(LOG_DEBUG, "krb5_get_init_creds_keytab: %d", (int)ret);
		goto icfk_cleanup;
	}

	ret = krb5_cc_default(context, &cc);
	if (ret) {
		syslog(LOG_DEBUG, "krb5_cc_default: %d", (int)ret);
		goto icfk_cleanup;
	}

	ret = krb5_cc_initialize(context, cc, me);
	if (ret) {
		syslog(LOG_DEBUG, "krb5_cc_initialize: %d", (int)ret);
		goto icfk_cleanup;
	}

	ret = krb5_cc_store_cred(context, cc, &my_creds);
	if (ret) {
		syslog(LOG_DEBUG, "krb5_cc_store_cred: %d", (int)ret);
		goto icfk_cleanup;
	}
out:
	my_creds.client = (krb5_principal)0;
	krb5_free_cred_contents(context, &my_creds);

	if (me)
		krb5_free_principal(context, me);
	if (keytab)
		krb5_kt_close(context, keytab);
	return cc;
icfk_cleanup:
	if (cc) {
		krb5_cc_close(context, cc);
		cc = NULL;
	}
	goto out;
}

static int
cifs_krb5_get_req(const char *host, krb5_ccache ccache,
		  DATA_BLOB * mechtoken, DATA_BLOB * sess_key)
{
	krb5_error_code ret;
	krb5_keyblock *tokb;
	krb5_creds in_creds, *out_creds;
	krb5_data apreq_pkt, in_data;
	krb5_auth_context auth_context = NULL;
#if defined(HAVE_KRB5_AUTH_CON_SETADDRS) && defined(HAVE_KRB5_AUTH_CON_SET_REQ_CKSUMTYPE)
	static const uint8_t gss_cksum[24] = { 0x10, 0x00, /* ... */};
#endif
	memset(&in_creds, 0, sizeof(in_creds));

	ret = krb5_cc_get_principal(context, ccache, &in_creds.client);
	if (ret) {
		syslog(LOG_DEBUG, "%s: unable to get client principal name",
		       __func__);
		return ret;
	}

	ret = krb5_sname_to_principal(context, host, "cifs", KRB5_NT_UNKNOWN,
					&in_creds.server);
	if (ret) {
		syslog(LOG_DEBUG, "%s: unable to convert sname to princ (%s).",
		       __func__, host);
		goto out_free_principal;
	}

	ret = krb5_get_credentials(context, 0, ccache, &in_creds, &out_creds);
	krb5_free_principal(context, in_creds.server);
	if (ret) {
		syslog(LOG_DEBUG, "%s: unable to get credentials for %s",
		       __func__, host);
		goto out_free_principal;
	}

	in_data.length = 0;
	in_data.data = NULL;

	ret = krb5_auth_con_init(context, &auth_context);
	if (ret) {
		syslog(LOG_DEBUG, "%s: unable to create auth_context: %d",
		       __func__, ret);
		goto out_free_creds;
	}

#if defined(HAVE_KRB5_AUTH_CON_SETADDRS) && defined(HAVE_KRB5_AUTH_CON_SET_REQ_CKSUMTYPE)
	/* Ensure we will get an addressless ticket. */
	ret = krb5_auth_con_setaddrs(context, auth_context, NULL, NULL);
	if (ret) {
		syslog(LOG_DEBUG, "%s: unable to set NULL addrs: %d",
		       __func__, ret);
		goto out_free_auth;
	}

	/*
	 * Create a GSSAPI checksum (0x8003), see RFC 4121.
	 *
	 * The current layout is
	 *
	 * 0x10, 0x00, 0x00, 0x00 - length = 16
	 * 0x00, 0x00, 0x00, 0x00 - channel binding info - 16 zero bytes
	 * 0x00, 0x00, 0x00, 0x00
	 * 0x00, 0x00, 0x00, 0x00
	 * 0x00, 0x00, 0x00, 0x00
	 * 0x00, 0x00, 0x00, 0x00 - flags
	 *
	 * GSS_C_NO_CHANNEL_BINDINGS means 16 zero bytes,
	 * this is needed to work against some closed source
	 * SMB servers.
	 *
	 * See https://bugzilla.samba.org/show_bug.cgi?id=7890
	 */
	in_data.data = discard_const_p(char, gss_cksum);
	in_data.length = 24;

	/* MIT krb5 < 1.7 is missing the prototype, but still has the symbol */
#if !HAVE_DECL_KRB5_AUTH_CON_SET_REQ_CKSUMTYPE
	krb5_error_code krb5_auth_con_set_req_cksumtype(
		krb5_auth_context auth_context,
		krb5_cksumtype    cksumtype);
#endif
	ret = krb5_auth_con_set_req_cksumtype(context, auth_context, 0x8003);
	if (ret) {
		syslog(LOG_DEBUG, "%s: unable to set 0x8003 checksum",
		       __func__);
		goto out_free_auth;
	}
#endif

	apreq_pkt.length = 0;
	apreq_pkt.data = NULL;
	ret = krb5_mk_req_extended(context, &auth_context, AP_OPTS_USE_SUBKEY,
				   &in_data, out_creds, &apreq_pkt);
	if (ret) {
		syslog(LOG_DEBUG, "%s: unable to make AP-REQ for %s",
		       __func__, host);
		goto out_free_auth;
	}

	ret = krb5_auth_con_getsendsubkey(context, auth_context, &tokb);
	if (ret) {
		syslog(LOG_DEBUG, "%s: unable to get session key for %s",
		       __func__, host);
		goto out_free_auth;
	}

	*mechtoken = data_blob(apreq_pkt.data, apreq_pkt.length);
	*sess_key = data_blob(KRB5_KEY_DATA(tokb), KRB5_KEY_LENGTH(tokb));

	krb5_free_keyblock(context, tokb);
out_free_auth:
	krb5_auth_con_free(context, auth_context);
out_free_creds:
	krb5_free_creds(context, out_creds);
out_free_principal:
	krb5_free_principal(context, in_creds.client);
	return ret;
}

/*
 * Prepares AP-REQ data for mechToken and gets session key
 * Uses credentials from cache. It will not ask for password
 * you should receive credentials for yuor name manually using
 * kinit or whatever you wish.
 *
 * in:
 * 	oid -		string with OID/ Could be OID_KERBEROS5
 * 			or OID_KERBEROS5_OLD
 * 	principal -	Service name.
 * 			Could be "cifs/FQDN" for KRB5 OID
 * 			or for MS_KRB5 OID style server principal
 * 			like "pdc$@YOUR.REALM.NAME"
 *
 * out:
 * 	secblob -	pointer for spnego wrapped AP-REQ data to be stored
 * 	sess_key-	pointer for SessionKey data to be stored
 *
 * ret: 0 - success, others - failure
 */
static int
handle_krb5_mech(const char *oid, const char *host, DATA_BLOB * secblob,
		 DATA_BLOB * sess_key, krb5_ccache ccache)
{
	int retval;
	DATA_BLOB tkt, tkt_wrapped;

	syslog(LOG_DEBUG, "%s: getting service ticket for %s", __func__, host);

	/* get a kerberos ticket for the service and extract the session key */
	retval = cifs_krb5_get_req(host, ccache, &tkt, sess_key);
	if (retval) {
		syslog(LOG_DEBUG, "%s: failed to obtain service ticket (%d)",
		       __func__, retval);
		return retval;
	}

	syslog(LOG_DEBUG, "%s: obtained service ticket", __func__);

	/* wrap that up in a nice GSS-API wrapping */
	tkt_wrapped = spnego_gen_krb5_wrap(tkt, TOK_ID_KRB_AP_REQ);

	/* and wrap that in a shiny SPNEGO wrapper */
	*secblob = gen_negTokenInit(oid, tkt_wrapped);

	data_blob_free(&tkt_wrapped);
	data_blob_free(&tkt);
	return retval;
}

#define DKD_HAVE_HOSTNAME	0x1
#define DKD_HAVE_VERSION	0x2
#define DKD_HAVE_SEC		0x4
#define DKD_HAVE_IP		0x8
#define DKD_HAVE_UID		0x10
#define DKD_HAVE_PID		0x20
#define DKD_HAVE_CREDUID	0x40
#define DKD_HAVE_USERNAME	0x80
#define DKD_MUSTHAVE_SET (DKD_HAVE_HOSTNAME|DKD_HAVE_VERSION|DKD_HAVE_SEC)

struct decoded_args {
	int ver;
	char *hostname;
	char *ip;
	char *username;
	uid_t uid;
	uid_t creduid;
	pid_t pid;
	sectype_t sec;
};

static unsigned int
decode_key_description(const char *desc, struct decoded_args *arg)
{
	int len;
	int retval = 0;
	char *pos;
	const char *tkn = desc;

	do {
		pos = index(tkn, ';');
		if (strncmp(tkn, "host=", 5) == 0) {

			if (pos == NULL)
				len = strlen(tkn);
			else
				len = pos - tkn;

			len -= 5;
			SAFE_FREE(arg->hostname);
			arg->hostname = strndup(tkn + 5, len);
			if (arg->hostname == NULL) {
				syslog(LOG_ERR, "Unable to allocate memory");
				return 1;
			}
			retval |= DKD_HAVE_HOSTNAME;
			syslog(LOG_DEBUG, "host=%s", arg->hostname);
		} else if (!strncmp(tkn, "ip4=", 4) || !strncmp(tkn, "ip6=", 4)) {
			if (pos == NULL)
				len = strlen(tkn);
			else
				len = pos - tkn;

			len -= 4;
			SAFE_FREE(arg->ip);
			arg->ip = strndup(tkn + 4, len);
			if (arg->ip == NULL) {
				syslog(LOG_ERR, "Unable to allocate memory");
				return 1;
			}
			retval |= DKD_HAVE_IP;
			syslog(LOG_DEBUG, "ip=%s", arg->ip);
		} else if (strncmp(tkn, "user=", 5) == 0) {
			if (pos == NULL)
				len = strlen(tkn);
			else
				len = pos - tkn;

			len -= 5;
			SAFE_FREE(arg->username);
			arg->username = strndup(tkn + 5, len);
			if (arg->username == NULL) {
				syslog(LOG_ERR, "Unable to allocate memory");
				return 1;
			}
			retval |= DKD_HAVE_USERNAME;
			syslog(LOG_DEBUG, "user=%s", arg->username);
		} else if (strncmp(tkn, "pid=", 4) == 0) {
			errno = 0;
			arg->pid = strtol(tkn + 4, NULL, 0);
			if (errno != 0) {
				syslog(LOG_ERR, "Invalid pid format: %s",
				       strerror(errno));
				return 1;
			}
			syslog(LOG_DEBUG, "pid=%u", arg->pid);
			retval |= DKD_HAVE_PID;
		} else if (strncmp(tkn, "sec=", 4) == 0) {
			if (strncmp(tkn + 4, "krb5", 4) == 0) {
				retval |= DKD_HAVE_SEC;
				arg->sec = KRB5;
			} else if (strncmp(tkn + 4, "mskrb5", 6) == 0) {
				retval |= DKD_HAVE_SEC;
				arg->sec = MS_KRB5;
			}
			syslog(LOG_DEBUG, "sec=%d", arg->sec);
		} else if (strncmp(tkn, "uid=", 4) == 0) {
			errno = 0;
			arg->uid = strtol(tkn + 4, NULL, 16);
			if (errno != 0) {
				syslog(LOG_ERR, "Invalid uid format: %s",
				       strerror(errno));
				return 1;
			}
			retval |= DKD_HAVE_UID;
			syslog(LOG_DEBUG, "uid=%u", arg->uid);
		} else if (strncmp(tkn, "creduid=", 8) == 0) {
			errno = 0;
			arg->creduid = strtol(tkn + 8, NULL, 16);
			if (errno != 0) {
				syslog(LOG_ERR, "Invalid creduid format: %s",
				       strerror(errno));
				return 1;
			}
			retval |= DKD_HAVE_CREDUID;
			syslog(LOG_DEBUG, "creduid=%u", arg->creduid);
		} else if (strncmp(tkn, "ver=", 4) == 0) {	/* if version */
			errno = 0;
			arg->ver = strtol(tkn + 4, NULL, 16);
			if (errno != 0) {
				syslog(LOG_ERR, "Invalid version format: %s",
				       strerror(errno));
				return 1;
			}
			retval |= DKD_HAVE_VERSION;
			syslog(LOG_DEBUG, "ver=%d", arg->ver);
		}
		if (pos == NULL)
			break;
		tkn = pos + 1;
	} while (tkn);
	return retval;
}

static int cifs_resolver(const key_serial_t key, const char *key_descr)
{
	int c;
	struct addrinfo *addr;
	char ip[INET6_ADDRSTRLEN];
	void *p;
	const char *keyend = key_descr;
	/* skip next 4 ';' delimiters to get to description */
	for (c = 1; c <= 4; c++) {
		keyend = index(keyend + 1, ';');
		if (!keyend) {
			syslog(LOG_ERR, "invalid key description: %s",
			       key_descr);
			return 1;
		}
	}
	keyend++;

	/* resolve name to ip */
	c = getaddrinfo(keyend, NULL, NULL, &addr);
	if (c) {
		syslog(LOG_ERR, "unable to resolve hostname: %s [%s]",
		       keyend, gai_strerror(c));
		return 1;
	}

	/* conver ip to string form */
	if (addr->ai_family == AF_INET)
		p = &(((struct sockaddr_in *)addr->ai_addr)->sin_addr);
	else
		p = &(((struct sockaddr_in6 *)addr->ai_addr)->sin6_addr);

	if (!inet_ntop(addr->ai_family, p, ip, sizeof(ip))) {
		syslog(LOG_ERR, "%s: inet_ntop: %s", __func__, strerror(errno));
		freeaddrinfo(addr);
		return 1;
	}

	/* setup key */
	c = keyctl_instantiate(key, ip, strlen(ip) + 1, 0);
	if (c == -1) {
		syslog(LOG_ERR, "%s: keyctl_instantiate: %s", __func__,
		       strerror(errno));
		freeaddrinfo(addr);
		return 1;
	}

	freeaddrinfo(addr);
	return 0;
}

/*
 * Older kernels sent IPv6 addresses without colons. Well, at least
 * they're fixed-length strings. Convert these addresses to have colon
 * delimiters to make getaddrinfo happy.
 */
static void convert_inet6_addr(const char *from, char *to)
{
	int i = 1;

	while (*from) {
		*to++ = *from++;
		if (!(i++ % 4) && *from)
			*to++ = ':';
	}
	*to = 0;
}

static int ip_to_fqdn(const char *addrstr, char *host, size_t hostlen)
{
	int rc;
	struct addrinfo hints = {.ai_flags = AI_NUMERICHOST };
	struct addrinfo *res;
	const char *ipaddr = addrstr;
	char converted[INET6_ADDRSTRLEN + 1];

	if ((strlen(ipaddr) > INET_ADDRSTRLEN) && !strchr(ipaddr, ':')) {
		convert_inet6_addr(ipaddr, converted);
		ipaddr = converted;
	}

	rc = getaddrinfo(ipaddr, NULL, &hints, &res);
	if (rc) {
		syslog(LOG_DEBUG, "%s: failed to resolve %s to "
		       "ipaddr: %s", __func__, ipaddr,
		       rc == EAI_SYSTEM ? strerror(errno) : gai_strerror(rc));
		return rc;
	}

	rc = getnameinfo(res->ai_addr, res->ai_addrlen, host, hostlen,
			 NULL, 0, NI_NAMEREQD);
	freeaddrinfo(res);
	if (rc) {
		syslog(LOG_DEBUG, "%s: failed to resolve %s to fqdn: %s",
		       __func__, ipaddr,
		       rc == EAI_SYSTEM ? strerror(errno) : gai_strerror(rc));
		return rc;
	}

	syslog(LOG_DEBUG, "%s: resolved %s to %s", __func__, ipaddr, host);
	return 0;
}

/* walk a string and lowercase it in-place */
static void
lowercase_string(char *c)
{
	while(*c) {
		*c = tolower(*c);
		++c;
	}
}

static void usage(void)
{
	fprintf(stderr, "Usage: %s [ -K /path/to/keytab] [-k /path/to/krb5.conf] [-t] [-v] [-l] key_serial\n", prog);
}

static const struct option long_options[] = {
	{"krb5conf", 1, NULL, 'k'},
	{"legacy-uid", 0, NULL, 'l'},
	{"trust-dns", 0, NULL, 't'},
	{"keytab", 1, NULL, 'K'},
	{"version", 0, NULL, 'v'},
	{NULL, 0, NULL, 0}
};

int main(const int argc, char *const argv[])
{
	struct cifs_spnego_msg *keydata = NULL;
	DATA_BLOB secblob = data_blob_null;
	DATA_BLOB sess_key = data_blob_null;
	key_serial_t key = 0;
	size_t datalen;
	unsigned int have;
	long rc = 1;
	int c, try_dns = 0, legacy_uid = 0;
	char *buf;
	char hostbuf[NI_MAXHOST], *host;
	struct decoded_args arg;
	const char *oid;
	uid_t uid;
	char *keytab_name = NULL;
	krb5_ccache ccache = NULL;

	hostbuf[0] = '\0';
	memset(&arg, 0, sizeof(arg));

	openlog(prog, 0, LOG_DAEMON);

	while ((c = getopt_long(argc, argv, "ck:K:ltv", long_options, NULL)) != -1) {
		switch (c) {
		case 'c':
			/* legacy option -- skip it */
			break;
		case 't':
			try_dns++;
			break;
		case 'k':
			if (setenv("KRB5_CONFIG", optarg, 1) != 0) {
				syslog(LOG_ERR, "unable to set $KRB5_CONFIG: %d", errno);
				goto out;
			}
			break;
		case 'K':
			keytab_name = optarg;
			break;
		case 'l':
			legacy_uid++;
			break;
		case 'v':
			rc = 0;
			printf("version: %s\n", VERSION);
			goto out;
		default:
			syslog(LOG_ERR, "unknown option: %c", c);
			goto out;
		}
	}

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

	rc = keyctl_describe_alloc(key, &buf);
	if (rc == -1) {
		syslog(LOG_ERR, "keyctl_describe_alloc failed: %s",
		       strerror(errno));
		rc = 1;
		goto out;
	}

	syslog(LOG_DEBUG, "key description: %s", buf);

	if ((strncmp(buf, "cifs.resolver", sizeof("cifs.resolver") - 1) == 0) ||
	    (strncmp(buf, "dns_resolver", sizeof("dns_resolver") - 1) == 0)) {
		rc = cifs_resolver(key, buf);
		goto out;
	}

	have = decode_key_description(buf, &arg);
	SAFE_FREE(buf);
	if ((have & DKD_MUSTHAVE_SET) != DKD_MUSTHAVE_SET) {
		syslog(LOG_ERR, "unable to get necessary params from key "
		       "description (0x%x)", have);
		rc = 1;
		goto out;
	}

	if (arg.ver > CIFS_SPNEGO_UPCALL_VERSION) {
		syslog(LOG_ERR, "incompatible kernel upcall version: 0x%x",
		       arg.ver);
		rc = 1;
		goto out;
	}

	if (strlen(arg.hostname) >= NI_MAXHOST) {
		syslog(LOG_ERR, "hostname provided by kernel is too long");
		rc = 1;
		goto out;

	}

	if (!legacy_uid && (have & DKD_HAVE_CREDUID))
		uid = arg.creduid;
	else if (have & DKD_HAVE_UID)
		uid = arg.uid;
	else {
		/* no uid= or creduid= parm -- something is wrong */
		syslog(LOG_ERR, "No uid= or creduid= parm specified");
		rc = 1;
		goto out;
	}

	rc = setuid(uid);
	if (rc == -1) {
		syslog(LOG_ERR, "setuid: %s", strerror(errno));
		goto out;
	}

	rc = krb5_init_context(&context);
	if (rc) {
		syslog(LOG_ERR, "unable to init krb5 context: %ld", rc);
		goto out;
	}

	ccache = get_default_cc();
	/* Couldn't find credcache? Try to use keytab */
	if (ccache == NULL && arg.username != NULL)
		ccache = init_cc_from_keytab(keytab_name, arg.username);

	if (ccache == NULL) {
		rc = 1;
		goto out;
	}

	host = arg.hostname;

	// do mech specific authorization
	switch (arg.sec) {
	case MS_KRB5:
	case KRB5:
		/*
		 * Andrew Bartlett's suggested scheme for picking a principal
		 * name, based on a supplied hostname.
		 *
		 * INPUT: fooo
		 * TRY in order:
		 * cifs/fooo@REALM
		 * cifs/fooo.<guessed domain ?>@REALM
		 *
		 * INPUT: bar.example.com
		 * TRY only:
		 * cifs/bar.example.com@REALM
		 */
		if (arg.sec == MS_KRB5)
			oid = OID_KERBEROS5_OLD;
		else
			oid = OID_KERBEROS5;

retry_new_hostname:
		lowercase_string(host);
		rc = handle_krb5_mech(oid, host, &secblob, &sess_key, ccache);
		if (!rc)
			break;

		/*
		 * If hostname has a '.', assume it's a FQDN, otherwise we
		 * want to guess the domainname.
		 */
		if (!strchr(host, '.')) {
			struct addrinfo hints;
			struct addrinfo *ai;
			char *domainname;
			char fqdn[NI_MAXHOST];

			/*
			 * use getaddrinfo() to resolve the hostname of the
			 * server and set ai_canonname.
			 */
			memset(&hints, 0, sizeof(hints));
			hints.ai_family = AF_UNSPEC;
			hints.ai_flags = AI_CANONNAME;
			rc = getaddrinfo(host, NULL, &hints, &ai);
			if (rc) {
				syslog(LOG_ERR, "Unable to resolve host address: %s [%s]",
				       host, gai_strerror(rc));
				break;
			}

			/* scan forward to first '.' in ai_canonnname */
			domainname = strchr(ai->ai_canonname, '.');
			if (!domainname) {
				rc = -EINVAL;
				freeaddrinfo(ai);
				break;
			}
			lowercase_string(domainname);
			rc = snprintf(fqdn, sizeof(fqdn), "%s%s",
					host, domainname);
			freeaddrinfo(ai);
			if (rc < 0 || (size_t)rc >= sizeof(fqdn)) {
				syslog(LOG_ERR, "Problem setting hostname in string: %ld", rc);
				rc = -EINVAL;
				break;
			}

			rc = handle_krb5_mech(oid, fqdn, &secblob, &sess_key, ccache);
			if (!rc)
				break;
		}

		if (!try_dns || !(have & DKD_HAVE_IP))
			break;

		rc = ip_to_fqdn(arg.ip, hostbuf, sizeof(hostbuf));
		if (rc)
			break;

		try_dns = 0;
		host = hostbuf;
		goto retry_new_hostname;
	default:
		syslog(LOG_ERR, "sectype: %d is not implemented", arg.sec);
		rc = 1;
		break;
	}

	if (rc) {
		syslog(LOG_DEBUG, "Unable to obtain service ticket");
		goto out;
	}

	/* pack SecurityBlob and SessionKey into downcall packet */
	datalen =
	    sizeof(struct cifs_spnego_msg) + secblob.length + sess_key.length;
	keydata = (struct cifs_spnego_msg *)calloc(sizeof(char), datalen);
	if (!keydata) {
		rc = 1;
		goto out;
	}
	keydata->version = arg.ver;
	keydata->flags = 0;
	keydata->sesskey_len = sess_key.length;
	keydata->secblob_len = secblob.length;
	memcpy(&(keydata->data), sess_key.data, sess_key.length);
	memcpy(&(keydata->data) + keydata->sesskey_len,
	       secblob.data, secblob.length);

	/* setup key */
	rc = keyctl_instantiate(key, keydata, datalen, 0);
	if (rc == -1) {
		syslog(LOG_ERR, "keyctl_instantiate: %s", strerror(errno));
		goto out;
	}

	/* BB: maybe we need use timeout for key: for example no more then
	 * ticket lifietime? */
	/* keyctl_set_timeout( key, 60); */
out:
	/*
	 * on error, negatively instantiate the key ourselves so that we can
	 * make sure the kernel doesn't hang it off of a searchable keyring
	 * and interfere with the next attempt to instantiate the key.
	 */
	if (rc != 0 && key == 0) {
		syslog(LOG_DEBUG, "Negating key");
		keyctl_negate(key, 1, KEY_REQKEY_DEFL_DEFAULT);
	}
	data_blob_free(&secblob);
	data_blob_free(&sess_key);
	if (ccache)
		krb5_cc_close(context, ccache);
	if (context)
		krb5_free_context(context);
	SAFE_FREE(arg.hostname);
	SAFE_FREE(arg.ip);
	SAFE_FREE(arg.username);
	SAFE_FREE(keydata);
	syslog(LOG_DEBUG, "Exit status %ld", rc);
	return rc;
}
