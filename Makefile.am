AM_CFLAGS = -Wall -Wextra -D_FORTIFY_SOURCE=2 $(PIE_CFLAGS) $(RELRO_CFLAGS)
ACLOCAL_AMFLAGS = -I aclocal

root_sbindir = $(ROOTSBINDIR)
root_sbin_PROGRAMS = mount.cifs
mount_cifs_SOURCES = mount.cifs.c mtab.c resolve_host.c util.c
mount_cifs_LDADD = $(LIBCAP) $(CAPNG_LDADD) $(RT_LDADD)

man_MANS = mount.cifs.8
include_HEADERS = cifsidmap.h

bin_PROGRAMS =
sbin_PROGRAMS =
clean-local: clean-local-upcall clean-local-idmap clean-local-cifsacl

if CONFIG_CIFSUPCALL
sbin_PROGRAMS += cifs.upcall
cifs_upcall_SOURCES = cifs.upcall.c data_blob.c asn1.c spnego.c
cifs_upcall_LDADD = -ltalloc -lkeyutils $(KRB5_LDADD)
man_MANS += cifs.upcall.8

#
# Fix the pathnames in manpages. To prevent @label@ being replaced by m4, we
# need to obfuscate the LHS of the regex (hence the trivial one character set).
#
cifs.upcall.8: cifs.upcall.8.in
	$(SED) 's,[@]sbindir@,$(sbindir),' $(srcdir)/$@.in > $@-t && mv $@-t $@
endif

clean-local-upcall:
if CONFIG_CIFSUPCALL
	rm -f cifs.upcall.8 cifs.upcall.8-t
endif

if CONFIG_CIFSCREDS
bin_PROGRAMS += cifscreds
cifscreds_SOURCES = cifscreds.c cifskey.c resolve_host.c util.c
cifscreds_LDADD = -lkeyutils
man_MANS += cifscreds.1
endif

if CONFIG_CIFSIDMAP
sbin_PROGRAMS += cifs.idmap
cifs_idmap_SOURCES = cifs.idmap.c idmap_plugin.c
cifs_idmap_LDADD = -lkeyutils -ldl
man_MANS += cifs.idmap.8

cifs.idmap.8: cifs.idmap.8.in
	$(SED) -e 's,[@]sbindir@,$(sbindir),' -e 's,[@]pluginpath@,$(pluginpath),' $(srcdir)/$@.in > $@-t && mv $@-t $@
endif

clean-local-idmap:
if CONFIG_CIFSIDMAP
	rm -f cifs.idmap.8 cifs.idmap.8-t
endif

if CONFIG_CIFSACL
bin_PROGRAMS += getcifsacl
getcifsacl_SOURCES = getcifsacl.c idmap_plugin.c
getcifsacl_LDADD = -ldl
man_MANS += getcifsacl.1

getcifsacl.1: getcifsacl.1.in
	$(SED) 's,[@]pluginpath@,$(pluginpath),' $(srcdir)/$@.in > $@-t && mv $@-t $@

bin_PROGRAMS += setcifsacl
setcifsacl_SOURCES = setcifsacl.c idmap_plugin.c
setcifsacl_LDADD = -ldl
man_MANS += setcifsacl.1

setcifsacl.1: setcifsacl.1.in
	$(SED) 's,[@]pluginpath@,$(pluginpath),' $(srcdir)/$@.in > $@-t && mv $@-t $@
endif

clean-local-cifsacl:
if CONFIG_CIFSACL
	rm -f getcifsacl.1 getcifsacl.1-t
	rm -f setcifsacl.1 setcifsacl.1-t
endif

if CONFIG_PLUGIN
plugindir = $(pkglibdir)
plugin_PROGRAMS = idmapwb.so
man_MANS += idmapwb.8

idmapwb.so: idmapwb.c
	$(CC) $(DEFS) $(CFLAGS) $(AM_CFLAGS) $(WBCLIENT_CFLAGS) $(LDFLAGS) -shared -fpic -o $@ $+ $(WBCLIENT_LIBS)

idmapwb.8: idmapwb.8.in
	$(SED) 's,[@]pluginpath@,$(pluginpath),' $(srcdir)/$@.in > $@-t && mv $@-t $@

endif

if CONFIG_PAM
pam_PROGRAMS = pam_cifscreds.so

pam_cifscreds.so: pam_cifscreds.c cifskey.c resolve_host.c util.c
	$(CC) $(DEFS) $(CFLAGS) $(AM_CFLAGS) $(LDFLAGS) -shared -fpic -o $@ $+ -lpam -lkeyutils
man_MANS += pam_cifscreds.8
endif

SUBDIRS = contrib
