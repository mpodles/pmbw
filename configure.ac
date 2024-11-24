# -*- mode: autoconf -*-

AC_PREREQ([2.71])

AC_INIT([pmbw],[0.6.3])
AC_CONFIG_SRCDIR(pmbw.cc)
AC_CONFIG_AUX_DIR(acscripts)

AC_CANONICAL_TARGET

AM_INIT_AUTOMAKE(foreign)
AM_MAINTAINER_MODE

# Check for Windows system and set compilation flag.

AC_MSG_CHECKING(building for Windows)
case "$target_os" in
    *cygwin* | *mingw32*)
        ON_WINDOWS=true
        AC_MSG_RESULT(yes)
        ;;
    *)
        ON_WINDOWS=false
        AC_MSG_RESULT(no)
        ;;
esac
AC_DEFINE_UNQUOTED(ON_WINDOWS, $ON_WINDOWS)

# set debug info flag if no optimization flags are set.

if test "$CXXFLAGS" == ""; then
    CXXFLAGS="-g -O2"
fi

# check for programs.

AC_PROG_CXX
AC_LANG([C++])

# test support for -march=x86-64 (older gcc's don't have it)

save_cxxflags="$CXXFLAGS"
CXXFLAGS="$CXXFLAGS -march=x86-64"
AC_MSG_CHECKING([whether $CXX supports -march=x86-64])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
  [AC_MSG_RESULT([yes])],
  [AC_MSG_RESULT([no]); CXXFLAGS="$save_cxxflags"]
)

# check for libraries.

AC_CHECK_LIB(pthread, pthread_mutex_init,
  [LIBS="$LIBS -lpthread"],
  [AC_MSG_ERROR(pthread library needed!)]
)

# AM_CXXFLAGS = -W -Wall  -I/usr/include
AC_CHECK_LIB(cap, cap_get_proc,
  [LIBS="$LIBS -lcap"],
  [AC_MSG_ERROR(libcap-dev library needed!)]
)

# AC_CHECK_HEADERS([dpu_statistics.h])
# AC_CHECK_LIB([dpu_counters], [measure_cycle_count ], [LIBS="$LIBS -ldpu_counters", ])

AC_CHECK_HEADERS([dpu_statistics.h], [AC_DEFINE([HAVE_DPU_STATISTICS_H], [1], [Define if dpu_statistics.h is available])])

AC_CHECK_LIB([dpu_counters], [measure_cycle_count], [
    LIBS="$LIBS -ldpu_counters"
    AC_DEFINE([HAVE_DPU_COUNTERS], [1], [Define if dpu_counters library is available])
])

# AC_CHECK_LIB([dpu_counters], [print_perf_measurements ])
# AC_CHECK_LIB([dpu_counters], [cleanup_perf ])
# AC_CHECK_LIB([dpu_counters], [prepare_perf_measurements])

if [ ! "$ON_WINDOWS" ]; then

   AC_CHECK_LIB(rt, clock_gettime,
     [LIBS="$LIBS -lrt"],
     [AC_MSG_ERROR(rt library needed!)]
   )

fi

HAVE_POSIX_MEMALIGN=0
AC_CHECK_LIB(c, posix_memalign, [HAVE_POSIX_MEMALIGN=1])
AC_DEFINE_UNQUOTED(HAVE_POSIX_MEMALIGN, $HAVE_POSIX_MEMALIGN)

# transform Makefiles

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
