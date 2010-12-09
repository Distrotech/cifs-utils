AM_CFLAGS = -Wall -Wextra
ACLOCAL_AMFLAGS = -I aclocal

root_sbindir = "/sbin"
root_sbin_PROGRAMS = mount.cifs
mount_cifs_SOURCES = mount.cifs.c mtab.c resolve_host.c util.c
mount_cifs_LDADD = $(LIBCAP) $(CAPNG_LDADD)

man_MANS = mount.cifs.8

if CONFIG_CIFSUPCALL
sbin_PROGRAMS = cifs.upcall
cifs_upcall_SOURCES = cifs.upcall.c data_blob.c asn1.c spnego.c util.c
cifs_upcall_LDADD = -ltalloc -lkeyutils $(KRB5_LDADD)
man_MANS += cifs.upcall.8

cifs.upcall.8: cifs.upcall.8.in
	sed 's,\@sbindir\@,$(sbindir),' < $(srcdir)/cifs.upcall.8.in > cifs.upcall.8

clean-local:
	rm -f cifs.upcall.8
endif

if CONFIG_CIFSCREDS
bin_PROGRAMS = cifscreds
cifscreds_SOURCES = cifscreds.c resolve_host.c util.c
cifscreds_LDADD = -lkeyutils
endif
