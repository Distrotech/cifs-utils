#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT([cifs-utils],[6.6],[linux-cifs@vger.kernel.org],[cifs-utils],[https://wiki.samba.org/index.php/LinuxCIFS_utils])
AC_CONFIG_SRCDIR([replace.h])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile contrib/Makefile contrib/request-key.d/Makefile])
AC_CONFIG_MACRO_DIR(aclocal)

AM_INIT_AUTOMAKE

# "enable" options
AC_ARG_ENABLE(pie,
	[AS_HELP_STRING([--enable-pie],[Produce position independent executables @<:@default=yes@:>@])],
	enable_pie=$enableval,
	enable_pie="maybe")

AC_ARG_ENABLE(relro,
	[AS_HELP_STRING([--enable-relro],[Enable relocations read-only support @<:@default=yes@:>@])],
	enable_relro=$enableval,
	enable_relro="maybe")

AC_ARG_ENABLE(cifsupcall,
	[AS_HELP_STRING([--enable-cifsupcall],[Create cifs.upcall binary @<:@default=yes@:>@])],
	enable_cifsupcall=$enableval,
	enable_cifsupcall="maybe")

AC_ARG_ENABLE(cifscreds,
	[AS_HELP_STRING([--enable-cifscreds],[Create cifscreds utility @<:@default=yes@:>@])],
	enable_cifscreds=$enableval,
	enable_cifscreds="maybe")

AC_ARG_ENABLE(cifsidmap,
	[AS_HELP_STRING([--enable-cifsidmap],[Create cifs.idmap binary @<:@default=yes@:>@])],
	enable_cifsidmap=$enableval,
	enable_cifsidmap="maybe")

AC_ARG_ENABLE(cifsacl,
	[AS_HELP_STRING([--enable-cifsacl],[Create get/set cifsacl binary @<:@default=yes@:>@])],
	enable_cifsacl=$enableval,
	enable_cifsacl="maybe")

AC_ARG_ENABLE(pam,
	[AS_HELP_STRING([--enable-pam],[Create cifscreds PAM module @<:@default=yes@:>@])],
	enable_pam=$enableval,
	enable_pam="maybe")

AC_ARG_ENABLE(systemd,
	[AS_HELP_STRING([--enable-systemd],[Enable systemd specific behavior for mount.cifs @<:@default=yes@:>@])],
	enable_systemd=$enableval,
	enable_systemd="maybe")

# "with" options
AC_ARG_WITH(idmap-plugin,
	[AS_HELP_STRING([--with-idmap-plugin=/path/to/plugin],[Define the path to the plugin that the idmapping infrastructure should use @<:@default=/etc/cifs-utils/idmap-plugin@:>@])],
	pluginpath=$withval,
	pluginpath="/etc/cifs-utils/idmap-plugin")
AC_DEFINE_UNQUOTED(IDMAP_PLUGIN_PATH, "$pluginpath", [Location of plugin that ID mapping infrastructure should use. (usually a symlink to real plugin)])
AC_SUBST([pluginpath])

AC_ARG_WITH(pamdir,
	[AC_HELP_STRING([--with-pamdir=DIR],[Where to install the PAM module @<:@default=$(libdir)/security@:>@])],
	pamdir=$withval,
	pamdir="\$(libdir)/security")
AC_SUBST([pamdir])

# check for ROOTSBINDIR environment var
if test -z $ROOTSBINDIR; then
	ROOTSBINDIR="/sbin"
	export ROOTSBINDIR
fi

AC_ARG_VAR(ROOTSBINDIR, [Location where files ordinarily under /sbin should be installed. Note: unaffected by --prefix. @<:@default=/sbin@:>@])

# Checks for programs.
AC_PROG_CC
AC_USE_SYSTEM_EXTENSIONS
AM_PROG_CC_C_O

# AC_PROG_SED is only avaliable in recent autoconf versions.
# Use AC_CHECK_PROG instead if AC_PROG_SED is not present.
ifdef([AC_PROG_SED],
      [AC_PROG_SED],
      [AC_CHECK_PROG(SED, sed, sed)])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_UID_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_CHECK_TYPES([ptrdiff_t, ssize_t, uint32_t, uint8_t])

# Checks for library functions.
AC_FUNC_GETMNTENT
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_STRNLEN

# check for required functions
AC_CHECK_FUNCS([alarm atexit endpwent getmntent getpass gettimeofday inet_ntop memset realpath setenv strchr strcmp strdup strerror strncasecmp strndup strpbrk strrchr strstr strtol strtoul tolower uname], , [AC_MSG_ERROR([necessary functions(s) not found])])

AC_CHECK_FUNCS(clock_gettime, [], [
  AC_CHECK_LIB(rt, clock_gettime, [
      AC_DEFINE(HAVE_CLOCK_GETTIME, 1)
	AC_DEFINE(HAVE_CLOCK_GETTIME,1,
		[Whether the clock_gettime func is there])
      RT_LDADD="-lrt"
        ])
  ])
AC_SUBST(RT_LDADD)

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h ctype.h fcntl.h inttypes.h limits.h mntent.h netdb.h stddef.h stdint.h stdbool.h stdlib.h stdio.h errno.h string.h strings.h sys/mount.h sys/param.h sys/socket.h sys/time.h syslog.h unistd.h], , [AC_MSG_ERROR([necessary header(s) not found])])

# do we have sys/fsuid.h and setfsuid()?
AC_CHECK_HEADERS([sys/fsuid.h])
AC_CHECK_FUNC(setfsuid, , [AC_MSG_ERROR([System does not support setfsuid()])])

# FIXME: add test(s) to autodisable these flags when compiler/linker don't support it
if test $enable_pie != "no"; then
	PIE_CFLAGS="-fpie -pie"
else
	PIE_CFLAGS=""
fi
AC_SUBST([PIE_CFLAGS])

if test $enable_relro != "no"; then
	RELRO_CFLAGS="-Wl,-z,relro,-z,now"
else
	RELRO_CFLAGS=""
fi
AC_SUBST([RELRO_CFLAGS])

if test $enable_cifsupcall != "no"; then
	AC_CHECK_HEADERS([krb5.h krb5/krb5.h])
	if test x$ac_cv_header_krb5_krb5_h != xyes ; then
		if test x$ac_cv_header_krb5_h != xyes ; then
			if test "$enable_cifsupcall" = "yes"; then
				AC_MSG_ERROR([krb5.h not found, consider installing krb5-devel or krb5-libs-devel.])
			else
				AC_MSG_WARN([krb5.h not found, consider installing krb5-devel or krb5-libs-devel. Disabling cifs.upcall.])
				enable_cifsupcall="no"
			fi
		fi
	fi
fi
if test $enable_cifsupcall != "no"; then
	if test x$ac_cv_header_krb5_krb5_h = xyes ; then
		krb5_include="#include <krb5/krb5.h>"
	fi
	if test x$ac_cv_header_krb5_h = xyes ; then
		krb5_include="#include <krb5.h>"
	fi

	AC_CACHE_CHECK([for keyvalue in krb5_keyblock],
		[ac_cv_have_krb5_keyblock_keyvalue],[
			AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[$krb5_include]], [[krb5_keyblock key; key.keyvalue.data = NULL;]])],[ac_cv_have_krb5_keyblock_keyvalue=yes],[ac_cv_have_krb5_keyblock_keyvalue=no])])
	if test x"$ac_cv_have_krb5_keyblock_keyvalue" = x"yes" ; then
		AC_DEFINE(HAVE_KRB5_KEYBLOCK_KEYVALUE,1,
			[Whether the krb5_keyblock struct has a keyvalue property])
	fi
fi
if test $enable_cifsupcall != "no"; then
	AC_CHECK_HEADERS([talloc.h], , [
				if test "$enable_cifsupcall" = "yes"; then
					AC_MSG_ERROR([talloc.h not found, consider installing libtalloc-devel.])
				else
					AC_MSG_WARN([talloc.h not found, consider installing libtalloc-devel. Disabling cifs.upcall.])
					enable_cifsupcall="no"
				fi
			])
fi
if test $enable_cifsupcall != "no" -o $enable_cifsidmap != "no"; then
	AC_CHECK_HEADERS([keyutils.h], , [
				if test "$enable_cifsupcall" = "yes"; then
					AC_MSG_ERROR([keyutils.h not found, consider installing keyutils-libs-devel.])
				else
					AC_MSG_WARN([keyutils.h not found, consider installing keyutils-libs-devel. Disabling cifs.upcall.])
					enable_cifsupcall="no"
				fi
				if test "$enable_cifsidmap" = "yes"; then
					AC_MSG_ERROR([keyutils.h not found, consider installing keyutils-libs-devel.])
				else
					AC_MSG_WARN([keyutils.h not found, consider installing keyutils-libs-devel. Disabling cifs.idmap.])
					enable_cifsidmap="no"
				fi
			])
fi
if test $enable_cifsupcall != "no"; then
	AC_CHECK_LIB([krb5], [krb5_init_context],
			[ KRB5_LDADD='-lkrb5' ],
			AC_MSG_ERROR([no functioning krb5 library found!]))
	AC_SUBST(KRB5_LDADD)
fi

# checks for wbclient.h and libwbclient.so library
AC_TEST_WBCHL

# test for presence of WBC_ID_TYPE_BOTH enum value
AC_TEST_WBC_IDMAP_BOTH

if test $enable_cifscreds != "no" -o $enable_pam != "no"; then
	AC_CHECK_HEADERS([keyutils.h], , [

				if test $enable_cifscreds = "yes" -o $enable_pam = "yes"; then
					AC_MSG_ERROR([keyutils.h not found, consider installing keyutils-libs-devel.])
				else
					AC_MSG_WARN([keyutils.h not found, consider installing keyutils-libs-devel. Disabling cifscreds and cifscreds PAM module.])
					enable_cifscreds="no"
					enable_pam="no"
				fi
			])
fi

if test $enable_pam != "no"; then
	AC_CHECK_HEADERS([security/pam_appl.h], , [

				if test $enable_pam = "yes"; then
					AC_MSG_ERROR([security/pam_appl.h not found, consider installing keyutils-libs-devel.])
				else
					AC_MSG_WARN([security/pam_appl.h not found, consider installing pam-devel. Disabling cifscreds PAM module.])
					enable_pam="no"
				fi
			])
fi

# ugly, but I'm not sure how to check for functions in a library that's not in $LIBS
cu_saved_libs=$LIBS
LIBS="$LIBS $KRB5_LDADD"

# determine whether we can use MIT's new 'krb5_auth_con_getsendsubkey' to extract the signing key
if test $enable_cifsupcall != "no"; then
	AC_CHECK_FUNCS([krb5_auth_con_getsendsubkey])
fi

# non-critical functions (we have workarounds for these)
if test $enable_cifsupcall != "no"; then
	AC_CHECK_FUNCS([krb5_principal_get_realm krb5_free_unparsed_name])
	AC_CHECK_FUNCS([krb5_auth_con_setaddrs krb5_auth_con_set_req_cksumtype])
fi

if test $enable_systemd != "no"; then
	AC_DEFINE(ENABLE_SYSTEMD, 1, [Enable systemd specific behavior for mount.cifs])
fi

# MIT krb5 < 1.7 does not have this declaration but does have the symbol
AC_CHECK_DECLS(krb5_auth_con_set_req_cksumtype, [], [], [#include <krb5.h>])

LIBS=$cu_saved_libs

AM_CONDITIONAL(CONFIG_CIFSUPCALL, [test "$enable_cifsupcall" != "no"])
AM_CONDITIONAL(CONFIG_CIFSCREDS, [test "$enable_cifscreds" != "no"])
AM_CONDITIONAL(CONFIG_CIFSIDMAP, [test "$enable_cifsidmap" != "no"])
AM_CONDITIONAL(CONFIG_CIFSACL, [test "$enable_cifsacl" != "no"])
AM_CONDITIONAL(CONFIG_PAM, [test "$enable_pam" != "no"])
AM_CONDITIONAL(CONFIG_PLUGIN, [test "$enable_cifsidmap" != "no" -o "$enable_cifsacl" != "no"])

LIBCAP_NG_PATH

if test "x$CAPNG_LDADD" = "x"; then
	AC_LIBCAP
fi
AC_OUTPUT
