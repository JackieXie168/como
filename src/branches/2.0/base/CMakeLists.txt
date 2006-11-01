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
  sniffers.c
  ieee80211frames.c
  radio.c
  asn.c
  ${COMO_SOURCE_DIR}/lib/bitmap.c
  ${COMO_SOURCE_DIR}/lib/hash.c
  ${COMO_SOURCE_DIR}/lib/heap.c
  ${COMO_SOURCE_DIR}/lib/macutils.c
  ${COMO_SOURCE_DIR}/lib/printpkt.c
  ${COMO_SOURCE_DIR}/lib/mempool.c
  ${COMO_SOURCE_DIR}/lib/uhash.c
  ${COMO_SOURCE_DIR}/lib/pattern_search.c
)

IF(ENABLE_PROFILING)
  SET(COMO_SRCS
    ${COMO_SRCS}
    profiling.c
    util-timers.c
  )
ENDIF(ENABLE_PROFILING)

#
# Create target for the filter parser
#
ADD_CUSTOM_TARGET(FilterLexic echo "Creating filter-syntax.c")
ADD_CUSTOM_TARGET(FilterSyntax echo "Creating filter-syntax.c")

#
# Create custom command for flex/lex (note the outputs)
#
ADD_CUSTOM_COMMAND(
	SOURCE ${COMO_SOURCE_DIR}/base/filter-lexic.l
	COMMAND ${FLEX_EXECUTABLE}
	ARGS -Pyf -o${COMO_BINARY_DIR}/base/filter-lexic.c
	    ${COMO_SOURCE_DIR}/base/filter-lexic.l
	TARGET FilterLexic
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
	TARGET FilterSyntax
	DEPENDS ${COMO_BINARY_DIR}/base/filter-lexic.c
	OUTPUTS ${COMO_BINARY_DIR}/base/filter-syntax.c
)

#
# Add filter-syntax.c to COMO_SRCS
#
SET(COMO_SRCS ${COMO_SRCS} ${COMO_BINARY_DIR}/base/filter-syntax.c)

#
# Since filter-syntax.c does not exist yet when cmake is run, mark
# it as generated
#
SET_SOURCE_FILES_PROPERTIES(${COMO_BINARY_DIR}/base/filter-lexic.c GENERATED)
SET_SOURCE_FILES_PROPERTIES(${COMO_BINARY_DIR}/base/filter-syntax.c GENERATED)

#
# Some versions of flex (at least 2.5.33) produce code with comparisons between
# signed and unsigned vars. This, combined with -Wall and -Werror, prevents CoMo
# to build. We add -Wno-sign-compare to gcc flags to work around this.
#
# (see bug #1468610 for the flex project at http://sf.net/projects/flex)
#
SET_SOURCE_FILES_PROPERTIES(${COMO_BINARY_DIR}/base/filter-syntax.c COMPILE_FLAGS -Wno-sign-compare)

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
IF (NOT APPLE)
SET_TARGET_PROPERTIES(como
  PROPERTIES
  LINK_FLAGS -Wl,--export-dynamic
)
ENDIF(NOT APPLE)

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

TARGET_LINK_LIBRARIES(como ${COMO_BINARY_DIR}/sniffers/libsniffers.a)

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
