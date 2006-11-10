#
# This module finds if bison is installed and determines where the
# executable are. This code sets the following variables:
#
#  MONO_FOUND  = true if mono found.
#  MONO_CFLAGS = c flags to build objects that use mono.
#  MONO_LIBS   = libraries to link to mono.
#

IF (MONO_CFLAGS) # already found, be quiet
    SET(MONO_FIND_QUIETLY TRUE)
ENDIF (MONO_CFLAGS)

FIND_PACKAGE(PKGCONFIG)

IF (NOT PKGCONFIG_FOUND)
    IF (MONO_FIND_REQUIRED)
        MESSAGE(FATAL_ERROR "Could NOT find MONO: depends on PKG-CONFIG")
    ELSE (MONO_FIND_REQUIRED)
        MESSAGE(STATUS "Looked for MONO - required PKG-CONFIG not found")
    ENDIF (MONO_FIND_REQUIRED)

ELSE(NOT PKGCONFIG_FOUND)
    EXEC_PROGRAM(${PKGCONFIG_EXECUTABLE}
      ARGS "--cflags mono"
      OUTPUT_VARIABLE MONO_CFLAGS)
    EXEC_PROGRAM(${PKGCONFIG_EXECUTABLE}
      ARGS "--libs mono"
      OUTPUT_VARIABLE MONO_LIBS)

    # consider pkg-config has succeeded if at least -lmono is among the libs.
    IF (MONO_LIBS MATCHES "-lmono")
        SET (MONO_FOUND TRUE)
    ENDIF (MONO_LIBS MATCHES "-lmono")

    IF (NOT MONO_FOUND AND NOT MONO_FIND_QUIETLY)
        MESSAGE(STATUS, "Looked for MONO with PKG-CONFIG.")
    ENDIF (NOT MONO_FOUND AND NOT MONO_FIND_QUIETLY)

    IF (NOT MONO_FOUND AND MONO_FIND_REQUIRED)
        MESSAGE(FATAL_ERROR "Could NOT find MONO cflags from PKG-CONFIG.")
    ENDIF (NOT MONO_FOUND AND MONO_FIND_REQUIRED)

    IF (MONO_FOUND AND NOT MONO_FIND_QUIETLY)
        MESSAGE(STATUS "Found MONO:\n\tcflags=${MONO_CFLAGS}\n\tlibs=${MONO_LIBS}")
    ENDIF (MONO_FOUND AND NOT MONO_FIND_QUIETLY)
ENDIF (NOT PKGCONFIG_FOUND)

MARK_AS_ADVANCED(MONO_CFLAGS)
MARK_AS_ADVANCED(MONO_LIBS)

