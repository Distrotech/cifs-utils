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
