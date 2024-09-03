dnl Process this file with autoconf 2.69+ to produce a configure script.
dnl
dnl Copyright (c) 2010-2018 Henrique de Moraes Holschuh
dnl
dnl This program is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation; either version 2 of the License, or
dnl (at your option) any later version.
dnl
dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl
dnl You should have received a copy of the GNU General Public License
dnl along with this program; if not, write to the Free Software
dnl Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

AC_PREREQ([2.69])
AC_INIT([iucode_tool], [2.3.1],
        [https://gitlab.com/iucode-tool/iucode-tool/issues],
        [iucode-tool],
        [https://gitlab.com/iucode-tool/iucode-tool/wikis/home])
AC_COPYRIGHT([Copyright (c) 2010-2018 Henrique de Moraes Holschuh])

AC_CONFIG_SRCDIR([iucode_tool.c])
AC_CANONICAL_HOST
AM_INIT_AUTOMAKE([1.13 gnu no-dist-gzip dist-xz -Wall])
AC_CONFIG_HEADERS([iucode_tool_config.h])
AC_CONFIG_MACRO_DIR([m4])

dnl Work around the lack of a way to set preferred *FLAGS
AC_ARG_ENABLE([extend-flags],
    [AC_HELP_STRING([--enable-extend-flags],
        [force configure to extend already-defined C/CPP/LDFLAGS])],
    [
        AC_MSG_NOTICE([will extend C/CPP/LDFLAGS])
        enable_cflags_setting=yes
        enable_cppflags_setting=yes
        enable_ldflags_setting=yes
        enable_extend_flags=yes
    ],
    [
        AC_MSG_CHECKING([whether configure.ac should try to override CFLAGS])
        if test "x${CFLAGS+set}" = xset; then
            enable_cflags_setting=no
        else
            enable_cflags_setting=yes
        fi
        AC_MSG_RESULT($enable_cflags_setting)

        dnl AC_MSG_CHECKING([whether configure.ac should try to override CPPFLAGS])
        dnl if test "x${CPPFLAGS+set}" = xset; then
        dnl     enable_cppflags_setting=no
        dnl else
        dnl     enable_cppflags_setting=yes
        dnl fi
        dnl AC_MSG_RESULT($enable_cppflags_setting)

        AC_MSG_CHECKING([whether configure.ac should try to override LDFLAGS])
        if test "x${LDFLAGS+set}" = xset; then
            enable_ldflags_setting=no
        else
            enable_ldflags_setting=yes
        fi
        AC_MSG_RESULT($enable_ldflags_setting)
    ])

dnl Before we get to the C compiler...
AC_USE_SYSTEM_EXTENSIONS

dnl Checks for programs
AC_PROG_CC

dnl Checks for headers
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h stdint.h stdlib.h string.h unistd.h time.h cpuid.h])

dnl Other important checks
AC_C_BIGENDIAN([AC_ERROR([This program does not work on big-endian systems])])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_INT32_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_STAT
AC_CHECK_FUNCS([memset strcasecmp strdup strerror strrchr strtoul strtoull timegm])

# Allow GNU Argp as a standalone lib, as an alternative to glibc
AC_SEARCH_LIBS([argp_parse], [argp], [],
    [AC_ERROR([An implementation of GNU Argp was not found, please install libargp])])

dnl important system extensions
AC_SYS_LARGEFILE
AC_CHECK_FUNCS([flockfile fgets_unlocked])

dnl -----------------
dnl Configure options
dnl -----------------

AC_ARG_WITH([default-kernel-device],
    [AS_HELP_STRING([--with-default-kernel-device=PATH],
         [default microcode device (/dev/cpu/microcode)])],
    [AS_IF([test "x$withval" = "x" || test "x$withval" = "xno"],
               [AC_ERROR([--without-kernel-device build unsupported])],
         [MICROCODE_DEVICE_DEFAULT="$withval"])],
    [MICROCODE_DEVICE_DEFAULT="/dev/cpu/microcode"])
AC_DEFINE_UNQUOTED(MICROCODE_DEVICE_DEFAULT, "$MICROCODE_DEVICE_DEFAULT",
    [Path to kernel microcode device])
AC_SUBST(MICROCODE_DEVICE_DEFAULT)

AC_ARG_WITH([default-firmware-dir],
    [AS_HELP_STRING([--with-default-firmware-dir=PATH],
          [default firmware loader directory (/lib/firmware/intel-ucode)])],
    [AS_IF([test "x$withval" = "x" || test "x$withval" = "xno"],
               [AC_ERROR([--without-default-firmware-dir build unsupported])],
          [MICROCODE_DIR_DEFAULT="$withval"])],
    [MICROCODE_DIR_DEFAULT="/lib/firmware/intel-ucode"])
AC_DEFINE_UNQUOTED(MICROCODE_DIR_DEFAULT, "$MICROCODE_DIR_DEFAULT",
    [Path to the kernel microcode firmware directory])
AC_SUBST(MICROCODE_DIR_DEFAULT)

AC_ARG_WITH([cpuid-device-parent],
    [AS_HELP_STRING([--with-cpuid-device-parent=PATH],
          [per-cpu devices parent directory (/dev/cpu)])],
    [AS_IF([test "x$withval" = "x" || test "x$withval" = "xno"],
               [AC_ERROR([use --disable-cpuid-device instead of --without-cpuid-device-parent])],
          [CPUID_DEVICE_PARENT="$withval"])],
    [CPUID_DEVICE_PARENT="/dev/cpu"])
AC_DEFINE_UNQUOTED(CPUID_DEVICE_PARENT, "$CPUID_DEVICE_PARENT",
    [path to the per-cpu tree of cpuid devices])
AC_SUBST(CPUID_DEVICE_PARENT)
AC_ARG_WITH([cpuid-device-base],
    [AS_HELP_STRING([--with-cpuid-device-base=PATH_FORMAT],
          [per-cpu cpuid device format string, relative to CPUID_DEVICE_PARENT (%s/cpuid)])],
    [AS_IF([test "x$withval" = "x" || test "x$withval" = "xno"],
               [AC_ERROR([use --disable-cpuid-device instead of --without-cpuid-device-base])],
          [CPUID_DEVICE_BASE="$withval"])],
    [CPUID_DEVICE_BASE="%s/cpuid"])
AC_DEFINE_UNQUOTED(CPUID_DEVICE_BASE, "$CPUID_DEVICE_BASE",
    [snprintf format string for the per-cpu cpuid device path, relative to CPUID_DEVICE_NAME])
AC_SUBST(CPUID_DEVICE_BASE)

AC_ARG_ENABLE([cpuid-device],
    [AS_HELP_STRING([--disable-cpuid-device],
	[disable support for the Linux cpuid device (cripples --scan-system=exact)])])
AS_IF([test "x${enable_cpuid_device}" != "xno"],
    [AC_DEFINE(USE_CPUID_DEVICE, [], [Support scanning every core using Linux cpuid device])])

AC_ARG_ENABLE([valgrind-build],
    [AS_HELP_STRING([--enable-valgrind-build],
        [build for valgrind testing])],
    [AS_IF([test "x$enableval" != "xno"],
               [AC_DEFINE(VALGRIND_BUILD, [], [Valgrind-friendly build])])
    ])

dnl -------------------------------------------
dnl Override hardcoded *FLAGS for GCC and Clang
dnl If this breaks your platform, file a bug
dnl -------------------------------------------

dnl Do it after most of the autoconf crap, as they tend to screw
dnl up when you have anything more complex than -O2 -g for CFLAGS.

dnl We could do most of these overrides through AM_*FLAGS, but
dnl that's a pain for distros and users to override (as in it breaks
dnl 'make CFLAGS="-O0"') and only to be used for stuff that is
dnl absolutely essential to the build.

dnl if test "${GCC}${enable_cppflags_setting}" = "yesyes" ; then
dnl     CPPFLAGS="<whatever>"
dnl fi
if test "x${GCC}${enable_cflags_setting}" = "xyesyes" ; then
    dnl in "extend mode", we will get either user-supplied,
    dnl or the autoconf-default CFLAGS
    if test "x${enable_extend_flags}" != "xyes"; then
        CFLAGS="-O3 -g"
    fi

    dnl We need to detect -Wunknown-warning without the use of -Werror.
    dnl -Werror would be unsafe, as it might eventually trigger on the
    dnl test source code.
    dnl
    dnl clang needs "-Werror=unknown-warning-option".
    dnl gcc exits with an error when trying to enable unknown warnings.
    AX_CHECK_COMPILE_FLAG([-Werror=unknown-warning-option],
        [CFLAGSERRUW="-Werror=unknown-warning-option"],
        [],
        [],
        [AC_LANG_SOURCE([[
            int
            main(void)
            {

                ;
                return 0;
            }
        ]])])

    dnl gcc and clang warnings the code is not supposed to trigger...
    AX_APPEND_COMPILE_FLAGS(
        [-Wall -Wextra -Wformat=2 -Werror=format-security dnl
         -Wformat-signedness -Wformat-overflow=2 -Wformat-truncation=2 dnl
         -Wtrampolines -Wcast-align -Wsign-conversion -Wnull-dereference dnl
         -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations dnl
         -Wredundant-decls -Wstrict-overflow -Winit-self -Wshadow dnl
         -Wrestrict -Wpointer-arith -Wlogical-op -Wbad-function-cast dnl
         -Wwrite-strings -Wduplicated-branches -Wduplicated-cond dnl
         -Walloca -Wvla -Walloc-zero -Walloc-size-larger-than=1073741824],
        [],
        [${CFLAGSERRUW}],
        [AC_LANG_SOURCE([[
            int
            main(void)
            {

                ;
                return 0;
            }
        ]])])

    dnl Do not move _FORTIFY_SOURCE to CPPFLAGS, otherwise bad things
    dnl happen when the user does 'make CFLAGS="-O0 -g"'.  Debian/Ubuntu
    dnl have fixes for this, but others don't.  We keep it in CFLAGS
    dnl where it will get overriden along with -O3/-O2.
    AC_MSG_CHECKING([whether _FORTIFY_SOURCE is already enabled])
    AC_LINK_IFELSE(
        [AC_LANG_SOURCE([[
            int
            main(void) {
            #ifndef _FORTIFY_SOURCE
                return 0;
            #else
            #error _FORTIFY_SOURCE already defined
            #endif
            }
        ]])],
        [
            AC_MSG_RESULT([no])
            dnl gcc manual says to avoid -Wp,-D like the plague and use
            dnl -D/-U directly.
            AX_APPEND_COMPILE_FLAGS([-D_FORTIFY_SOURCE=2], [], [],
                [AC_LANG_SOURCE([[
                    int
                    main(int argc, char *argv[])
                    {
                        char arr[64], *dst = arr, *src = argv[0];
                        if (argc && src) { while (*src) { *dst++ = *src++; } }
                            return 0;
                    }
                ]])])
        ],
        [
            AC_MSG_RESULT([yes])
        ])

    AX_APPEND_COMPILE_FLAGS([-fstack-protector-strong -Wstack-protector],
        [],
        [],
        [AC_LANG_SOURCE([[
            int
            main(int argc, char *argv[])
            {
                char arr[64], *dst = arr, *src = argv[0];
                if (argc && src) { while (*src) { *dst++ = *src++; } }
                    return 0;
            }
        ]])])
fi
if test "x${GCC}${enable_ldflags_setting}" = "xyesyes" ; then
    AX_APPEND_LINK_FLAGS([-Wl,-z,relro -Wl,-z,now], [], [],
        [AC_LANG_SOURCE([[
            int
            main(int argc, char *argv[])
            {
                char arr[64], *dst = arr, *src = argv[0];
                if (argc && src) { while (*src) { *dst++ = *src++; } }
                    return 0;
            }
        ]])])
fi
if test "x${GCC}${enable_ldflags_setting}${enable_cflags_setting}" = "xyesyesyes" ; then
    AC_MSG_NOTICE([checking for Position Independent Executables (PIE) support])
    OCFLAGS="${CFLAGS}"
    AX_CHECK_COMPILE_FLAG([-fPIE],
        [
            CFLAGS="${CFLAGS} -fPIE"
            AX_CHECK_LINK_FLAG([-fPIE -pie],
                [LDFLAGS="${LDFLAGS} -fPIE -pie"
                 AC_MSG_NOTICE([PIE generation enabled])],
                [CFLAGS="${OCFLAGS}"
                 AC_MSG_NOTICE([PIE generation not supported by linker])],
                [],
                [AC_LANG_SOURCE([[
                    int
                    main(void)
                    {

                        ;
                        return 0;
                    }
                ]])])
        ],
        [AC_MSG_NOTICE([PIE generation not supported by compiler])],
        [],
        [AC_LANG_SOURCE([[
            int
            main(void)
            {

                ;
                return 0;
            }
        ]])])
fi

dnl --------------------------
dnl autoconf output generation
dnl --------------------------

AC_MSG_NOTICE([project-wide base CPPFLAGS: $CPPFLAGS])
AC_MSG_NOTICE([project-wide base CFLAGS:   $CFLAGS])
AC_MSG_NOTICE([project-wide base LDFLAGS:  $LDFLAGS])

AC_CONFIG_FILES([Makefile iucode_tool.8])
AC_OUTPUT
