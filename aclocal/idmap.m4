dnl Check for wbclient package
dnl

AC_DEFUN([AC_TEST_WBCHL],[
if test $enable_cifsidmap != "no" -o $enable_cifsacl != "no"; then
	PKG_CHECK_MODULES(WBCLIENT, wbclient, , [
				if test "$enable_cifsidmap" = "yes"; then
					AC_MSG_ERROR([wbclient.h not found, consider installing libwbclient-devel.])
				else
					AC_MSG_WARN([wbclient.h not found, consider installing libwbclient-devel. Disabling cifs.idmap.])
					enable_cifsidmap="no"
				fi
				if test "$enable_cifsacl" = "yes"; then
					AC_MSG_ERROR([wbclient.h not found, consider installing libwbclient-devel.])
				else
					AC_MSG_WARN([wbclient.h not found, consider installing libwbclient-devel. Disabling cifsacl.])
					enable_cifsacl="no"
				fi
			])
fi

if test $enable_cifsacl != "no"; then
	AC_CHECK_HEADERS([sys/xattr.h], , [
				if test "$enable_cifsacl" = "yes"; then
					AC_MSG_ERROR([/usr/include/sys/xattr.h not found])
				else
					AC_MSG_WARN([/usr/include/sys/xattr.h not found. Disabling cifsacl.])
					enable_cifsacl="no"
				fi
			], [ ])
fi
])

AC_DEFUN([AC_TEST_WBC_IDMAP_BOTH],[
	AC_MSG_CHECKING([whether WBC_ID_TYPE_BOTH enum value is defined])
	AC_LANG_PUSH([C])
	ac_wbc_save_CFLAGS="$CFLAGS"
	CFLAGS="$CFLAGS $WBCLIENT_CFLAGS"
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([#include <stdint.h>
#include <stdbool.h>
#include <wbclient.h>], [enum wbcIdType id = WBC_ID_TYPE_BOTH;])],
			  AC_DEFINE(HAVE_WBC_ID_TYPE_BOTH, 1, [Does wbclient.h have a WBC_ID_TYPE_BOTH enum?])
			  AC_MSG_RESULT([yes]), AC_MSG_RESULT([no]))
	CFLAGS=$ac_wbc_save_CFLAGS
	AC_LANG_POP([C])
])
