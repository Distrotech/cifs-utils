#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([cifs-utils], [4.0], [jlayton@samba.org])
AC_CONFIG_SRCDIR([replace.h])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])

AM_INIT_AUTOMAKE([cifs-utils], [4.0])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_USE_SYSTEM_EXTENSIONS
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h limits.h mntent.h netdb.h stddef.h stdint.h stdlib.h string.h strings.h sys/mount.h sys/param.h sys/socket.h sys/time.h syslog.h unistd.h krb5.h talloc.h], , [AC_MSG_ERROR([necessary header(s) not found])])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_UID_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T
AC_CHECK_TYPES([ptrdiff_t])

# Checks for library functions.
AC_FUNC_GETMNTENT
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_STRNLEN

# check for required functions
AC_CHECK_FUNCS([alarm atexit endpwent getmntent getpass gettimeofday inet_ntop memset realpath setenv strchr strdup strerror strncasecmp strndup strpbrk strrchr strstr strtol strtoul uname], , [AC_MSG_ERROR([necessary functions(s) not found])])

# non-critical functions (we have workarounds for these)
AC_CHECK_FUNCS([krb5_principal_get_realm krb5_free_unparsed_name])

AC_OUTPUT
