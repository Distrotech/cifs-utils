#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT([cifs-utils], [4.0], [jlayton@samba.org])
AC_CONFIG_SRCDIR([replace.h])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])

AM_INIT_AUTOMAKE([cifs-utils], [4.0])

# "with" options
AC_ARG_ENABLE(cifsupcall,
	[AC_HELP_STRING([--enable-cifsupcall],
			[Create cifs.upcall binary @<:@default=yes@:>@])],
	enable_cifsupcall=$enableval,
	enable_cifsupcall="maybe")

# Checks for programs.
AC_PROG_CC
AC_GNU_SOURCE

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h limits.h mntent.h netdb.h stddef.h stdint.h stdlib.h string.h strings.h sys/mount.h sys/param.h sys/socket.h sys/time.h syslog.h unistd.h], , [AC_MSG_ERROR([necessary header(s) not found])])

if test $enable_cifsupcall != "no"; then
	AC_CHECK_HEADERS([krb5/krb5.h], ,[
				if test "$enable_cifsupcall" = "yes"; then
					AC_MSG_ERROR([krb5/krb5.h not found, consider installing krb5-libs-devel.])
				else
					AC_MSG_WARN([krb5/krb5.h not found, consider installing krb5-libs-devel. Disabling cifs.upcall.])
					enable_cifsupcall="no"
				fi
			])
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
if test $enable_cifsupcall != "no"; then
	AC_CHECK_HEADERS([keyutils.h], , [
				if test "$enable_cifsupcall" = "yes"; then
					AC_MSG_ERROR([keyutils.h not found, consider installing keyutils-libs-devel.])
				else
					AC_MSG_WARN([keyutils.h not found, consider installing keyutils-libs-devel. Disabling cifs.upcall.])
					enable_cifsupcall="no"
				fi
			])
fi

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
AC_CHECK_FUNCS([alarm atexit endpwent getmntent getpass gettimeofday inet_ntop memset realpath setenv strchr strdup strerror strncasecmp strndup strpbrk strrchr strstr strtol strtoul uname], , [AC_MSG_ERROR([necessary functions(s) not found])])

# non-critical functions (we have workarounds for these)
if test $enable_cifsupcall != "no"; then
	AC_CHECK_FUNCS([krb5_principal_get_realm krb5_free_unparsed_name])
fi

AM_CONDITIONAL(CONFIG_CIFSUPCALL, [test "$enable_cifsupcall" != "no"])

AC_OUTPUT
