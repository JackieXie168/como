#
# This module finds if bison is installed and determines where the
# executable are. This code sets the following variables:
#
#  FLEX_EXECUTABLE      = the full path to FLEX
#  FLEX_FOUND           = true if FLEX found.
#
# $Id$

IF (FLEX_EXECUTABLE)
  # Already in cache, be silent
  SET(FLEX_FIND_QUIETLY TRUE)
ENDIF (FLEX_EXECUTABLE)

SET(FLEX_NAMES flex)
FIND_PROGRAM(FLEX_EXECUTABLE NAMES ${FLEX_NAMES})

IF (FLEX_EXECUTABLE)
   SET(FLEX_FOUND TRUE)
ELSE (FLEX_EXECUTABLE)
   SET(FLEX_FOUND FALSE)
ENDIF (FLEX_EXECUTABLE)

IF (FLEX_FOUND)
   IF (NOT FLEX_FIND_QUIETLY)
      MESSAGE(STATUS "Found FLEX: ${FLEX_EXECUTABLE}")
   ENDIF (NOT FLEX_FIND_QUIETLY)
ELSE (FLEX_FOUND)
   IF (FLEX_FIND_REQUIRED)
      MESSAGE(STATUS "Looked for FLEX executable named ${FLEX_NAMES}.")
      MESSAGE(FATAL_ERROR "Could NOT find FLEX executable")
   ENDIF (FLEX_FIND_REQUIRED)
ENDIF (FLEX_FOUND)

MARK_AS_ADVANCED(FLEX_EXECUTABLE)

