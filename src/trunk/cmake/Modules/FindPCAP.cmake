# - Find PCAP
# Find the native PCAP includes and library
#
#  PCAP_INCLUDE_DIR - where to find pcap.h, etc.
#  PCAP_LIBRARIES   - List of libraries when using PCAP.
#  PCAP_FOUND       - True if PCAP found.


IF (PCAP_INCLUDE_DIR)
  # Already in cache, be silent
  SET(PCAP_FIND_QUIETLY TRUE)
ENDIF (PCAP_INCLUDE_DIR)

FIND_PATH(PCAP_INCLUDE_DIR pcap.h
  /usr/local/include
  /usr/include
)

SET(PCAP_NAMES pcap)
FIND_LIBRARY(PCAP_LIBRARY
  NAMES ${PCAP_NAMES}
  PATHS /usr/lib /usr/local/lib
)

IF (PCAP_INCLUDE_DIR AND PCAP_LIBRARY)
   SET(PCAP_FOUND TRUE)
    SET( PCAP_LIBRARIES ${PCAP_LIBRARY} )
ELSE (PCAP_INCLUDE_DIR AND PCAP_LIBRARY)
   SET(PCAP_FOUND FALSE)
   SET( PCAP_LIBRARIES )
ENDIF (PCAP_INCLUDE_DIR AND PCAP_LIBRARY)

IF (PCAP_FOUND)
   IF (NOT PCAP_FIND_QUIETLY)
      MESSAGE(STATUS "Found PCAP: ${PCAP_LIBRARY}")
   ENDIF (NOT PCAP_FIND_QUIETLY)
ELSE (PCAP_FOUND)
   IF (PCAP_FIND_REQUIRED)
      MESSAGE(STATUS "Looked for PCAP library named ${PCAPS_NAMES}.")
      MESSAGE(FATAL_ERROR "Could NOT find PCAP library")
   ENDIF (PCAP_FIND_REQUIRED)
ENDIF (PCAP_FOUND)

MARK_AS_ADVANCED(
  PCAP_LIBRARY
  PCAP_INCLUDE_DIR
  )

