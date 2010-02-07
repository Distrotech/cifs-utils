root_sbindir = "/sbin"
root_sbin_PROGRAMS = mount.cifs
mount_cifs_SOURCES = mount.cifs.c mtab.c

sbin_PROGRAMS = cifs.upcall
cifs_upcall_SOURCES = cifs.upcall.c data_blob.c asn1.c spnego.c
cifs_upcall_LDADD = -ltalloc -lkrb5
