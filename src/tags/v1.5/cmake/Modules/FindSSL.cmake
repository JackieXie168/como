# - Find libssl and openssl md5.h
# Find the native ssl includes and library
#
#  SSLLIB_INCLUDE_DIR - where to find md5.h, etc.
#  SSLLIB_LIBRARIES   - List of libraries when using SSLLIB.
#  SSLLIB_FOUND       - True if SSLLIB found.

IF (SSLLIB_INCLUDE_DIR)
  # Already in cache, be silent
  SET(SSLLIB_FIND_QUIETLY TRUE)
ENDIF (SSLLIB_INCLUDE_DIR)

FIND_PATH(SSLLIB_INCLUDE_DIR md5.h
  /usr/local/include/openssl
  /usr/include/openssl
)

SET(SSLLIB_NAMES ssl)

FIND_LIBRARY(SSLLIB_LIBRARY
  NAMES ${SSLLIB_NAMES}
  PATHS /usr/lib /usr/local/lib
)

IF (SSLLIB_INCLUDE_DIR AND SSLLIB_LIBRARY)
   SET(SSLLIB_FOUND TRUE)
   SET( SSLLIB_LIBRARIES ${SSLLIB_LIBRARY})
ELSE (SSLLIB_INCLUDE_DIR AND SSLLIB_LIBRARY)
   SET(SSLLIB_FOUND FALSE)
   SET( SSLLIB_LIBRARIES )
ENDIF (SSLLIB_INCLUDE_DIR AND SSLLIB_LIBRARY)

IF (SSLLIB_FOUND)
   IF (NOT SSLLIB_FIND_QUIETLY)
      MESSAGE(STATUS "Found SSLLIB: ${SSLLIB_LIBRARY}")
   ENDIF (NOT SSLLIB_FIND_QUIETLY)
ELSE (SSLLIB_FOUND)
   IF (SSLLIB_FIND_REQUIRED)
      MESSAGE(STATUS "Looked for ssl library named ${SSLLIBS_NAMES}.")
      MESSAGE(FATAL_ERROR "Could NOT find ssl library")
   ENDIF (SSLLIB_FIND_REQUIRED)
ENDIF (SSLLIB_FOUND)

MARK_AS_ADVANCED(
  SSLLIB_LIBRARY
  SSLLIB_INCLUDE_DIR
  )


