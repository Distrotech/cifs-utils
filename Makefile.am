AM_CFLAGS = -Wall
root_sbindir = "/sbin"
root_sbin_PROGRAMS = mount.cifs
mount_cifs_SOURCES = mount.cifs.c mtab.c util.c

sbin_PROGRAMS = cifs.upcall
cifs_upcall_SOURCES = cifs.upcall.c data_blob.c asn1.c spnego.c util.c
cifs_upcall_LDADD = -ltalloc -lkrb5 -lkeyutils

man_MANS = cifs.upcall.8 mount.cifs.8
