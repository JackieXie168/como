INCLUDE_DIRECTORIES(${COMO_SOURCE_DIR}/include)
INCLUDE_DIRECTORIES(${COMO_SOURCE_DIR}/base)

SET(COMO_SRCS
  como.c
  logging.c
  memory.c
  config.c
  inline.c
  os.c
  util-io.c
  util-safe.c
  util-misc.c
  util-socket.c
  util-process.c
  ipc.c
  modules.c
  query.c
  query-comms.c
  query-ondemand.c
  services.c
  metadesc.c
  pktmeta.c
  headerinfo.c
  capture.c
  capture-client.c
  export.c
  supervisor.c
  storage.c
  storage-client.c
  ${COMO_SOURCE_DIR}/sniffers/sniffers.c
  ${COMO_SOURCE_DIR}/sniffers/ieee80211frames.c
  ${COMO_SOURCE_DIR}/sniffers/radio.c
  ${COMO_SOURCE_DIR}/lib/bitmap.c
  ${COMO_SOURCE_DIR}/lib/hash.c
  ${COMO_SOURCE_DIR}/lib/heap.c
  ${COMO_SOURCE_DIR}/lib/uhash.c
)

IF(ENABLE_PROFILING)
  SET(COMO_SRCS
    ${COMO_SRCS}
    profiling.c
    util-timers.c
  )
ENDIF(ENABLE_PROFILING)

#
# Sniffers always compiled
#
SET(SNIFFERS
  como
  ondemand
  pcap
  sflow
)

#
# Sniffers specific to UNIX
#
IF(UNIX)
# libpcap support
  IF(PCAP_FOUND)
    SET(SNIFFERS
      ${SNIFFERS}
      libpcap
    )
    INCLUDE_DIRECTORIES(${PCAP_INCLUDE_DIR})
  ENDIF(PCAP_FOUND)
  
# flow-tools support
  IF(FTLIB_FOUND)
    SET(SNIFFERS
      ${SNIFFERS}
      flowtools
      netflow
    )
    INCLUDE_DIRECTORIES(${FTLIB_INCLUDE_DIR})
  ENDIF(FTLIB_FOUND)

# DAG support
  IF(DAG_FOUND)
    SET(SNIFFERS
      ${SNIFFERS}
      erf
      dag
    )
    INCLUDE_DIRECTORIES(${DAG_INCLUDE_DIR})
  ENDIF(DAG_FOUND)

ENDIF(UNIX)

#
# Sniffers specific to Linux
#
IF(LINUX)
  SET(SNIFFERS
    ${SNIFFERS}
    radio
  )
ENDIF(LINUX)

#
# Sniffers specific to FreeBSD
#
IF(FREEBSD)
  SET(SNIFFERS
    ${SNIFFERS}
    bpf
  )
ENDIF(FREEBSD)

#
# Add sniffer sources to COMO_SRCS
#
FOREACH(sniffer ${SNIFFERS})
  SET(COMO_SRCS ${COMO_SRCS} ${COMO_SOURCE_DIR}/sniffers/sniffer-${sniffer}.c)
ENDFOREACH(sniffer)

#
# Write sniffer-list.h
#
SET(SNIFFER_LIST ${COMO_BINARY_DIR}/include/sniffer-list.h)
WRITE_FILE(${SNIFFER_LIST} "/* generated file, do not edit */")

FOREACH(sniffer ${SNIFFERS})
  WRITE_FILE(${SNIFFER_LIST} "extern sniffer_cb_t como_${sniffer}_sniffer;" APPEND)
ENDFOREACH(sniffer)

WRITE_FILE(${SNIFFER_LIST} "sniffer_cb_t *__sniffers[] = {" APPEND)

FOREACH(sniffer ${SNIFFERS})
  WRITE_FILE(${SNIFFER_LIST} "    &como_${sniffer}_sniffer," APPEND)
ENDFOREACH(sniffer)

WRITE_FILE(${SNIFFER_LIST} "    NULL };" APPEND)

#
# Create target for the filter parser
#
ADD_CUSTOM_TARGET(FilterSintax echo "Creating filter-syntax.c")

#
# Create custom command for flex/lex (note the outputs)
#
ADD_CUSTOM_COMMAND(
	SOURCE ${COMO_SOURCE_DIR}/base/filter-lexic.l
	COMMAND ${FLEX_EXECUTABLE}
	ARGS -Pyf -o${COMO_BINARY_DIR}/base/filter-lexic.c
	    ${COMO_SOURCE_DIR}/base/filter-lexic.l
	TARGET FilterSintax
	OUTPUTS ${COMO_BINARY_DIR}/base/filter-lexic.c
)

#
# Create custom command for bison/flex (note the DEPENDS)
#
ADD_CUSTOM_COMMAND(
	SOURCE ${COMO_SOURCE_DIR}/base/filter-syntax.y
	COMMAND ${BISON_EXECUTABLE} 
	ARGS -p yf -y ${COMO_SOURCE_DIR}/base/filter-syntax.y
	    -o ${COMO_BINARY_DIR}/base/filter-syntax.c
	TARGET FilterSintax
	DEPENDS ${COMO_BINARY_DIR}/base/filter-lexic.c
	OUTPUTS ${COMO_BINARY_DIR}/base/filter-syntax.c
)

#
# Add filter-syntax.c to COMO_SRCS
#
SET(COMO_SRCS ${COMO_SRCS} ${COMO_BINARY_DIR}/base/filter-syntax.c)

#
# Since filter-syntax.c does not exists yet when cmake is run, mark
# it as generated
#
SET_SOURCE_FILES_PROPERTIES(${COMO_BINARY_DIR}/base/filter-lexic.c GENERATED)
SET_SOURCE_FILES_PROPERTIES(${COMO_BINARY_DIR}/base/filter-syntax.c GENERATED)

#
# Include binary directory to include filter-lexic.c and filter-syntax.c
#
INCLUDE_DIRECTORIES(${COMO_BINARY_DIR}/base)

#
# Define the como executable
#
ADD_EXECUTABLE(como ${COMO_SRCS})
#
# Make sure modules can see como's symbols
#
SET_TARGET_PROPERTIES(como
  PROPERTIES
  LINK_FLAGS -Wl,--export-dynamic
)

#
# Add profiling information
#
IF(ENABLE_PROFILING)
  SET_TARGET_PROPERTIES(como
    PROPERTIES
    LINK_FLAGS -pg
  )
ENDIF(ENABLE_PROFILING)

#
# Libraries
#
IF(NOT ENABLE_SHARED_MODULES)
  TARGET_LINK_LIBRARIES(como ${COMO_BINARY_DIR}/modules/libmodules.a)
ENDIF(NOT ENABLE_SHARED_MODULES)

TARGET_LINK_LIBRARIES(como ${COMO_BINARY_DIR}/services/libservices.a)

TARGET_LINK_LIBRARIES(como m)

IF(LINUX)
  TARGET_LINK_LIBRARIES(como dl)
ENDIF(LINUX)

# pcap is dlopened
#IF(PCAP_FOUND)
#  TARGET_LINK_LIBRARIES(como ${PCAP_LIBRARIES})
#ENDIF(PCAP_FOUND)

IF(FTLIB_FOUND)
  TARGET_LINK_LIBRARIES(como ${FTLIB_LIBRARIES})
ENDIF(FTLIB_FOUND)

IF(DAG_FOUND)
  TARGET_LINK_LIBRARIES(como ${DAG_LIBRARIES})
ENDIF(DAG_FOUND)

#
# Installation
#
INSTALL_TARGETS(${INST_BINDIR} como)
