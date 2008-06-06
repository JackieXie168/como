# $Id$

INCLUDE_DIRECTORIES(${COMO_SOURCE_DIR}/include)
INCLUDE_DIRECTORIES(${COMO_SOURCE_DIR}/base)

IF(ENABLE_LOADSHED)
  INCLUDE_DIRECTORIES(${COMO_SOURCE_DIR}/loadshed)
ENDIF(ENABLE_LOADSHED)

SET(COMO_SRCS
  alc.c
  array.c
  asn.c
  capture.c
  config.c
  eventloop.c
  export.c
  hash.c
  headerinfo.c
  ieee80211frames.c
  ipc.c
  log.c
  mdl.c
  memory.c
  metadesc.c
  pktmeta.c
  pool.c
  query-comms.c
  query-ondemand.c
  query.c
  radio.c
  services.c
  setproctitle.c
  shobj.c
  sniffers.c
  socket.c
  storage-client.c
  storage.c
  supervisor.c
  util-io.c
  util-process.c
  util-safe.c
  util-timers.c
  ${COMO_SOURCE_DIR}/lib/uhash.c
  ${COMO_SOURCE_DIR}/lib/flowtable.c
  ${COMO_SOURCE_DIR}/lib/bitmap.c
#  ${COMO_SOURCE_DIR}/lib/hash.c
#  ${COMO_SOURCE_DIR}/lib/heap.c
#  ${COMO_SOURCE_DIR}/lib/macutils.c
#  ${COMO_SOURCE_DIR}/lib/printpkt.c
#  ${COMO_SOURCE_DIR}/lib/mempool.c
#  ${COMO_SOURCE_DIR}/lib/pattern_search.c
)

IF(ENABLE_PROFILING)
  SET(COMO_SRCS
    ${COMO_SRCS}
    profiling.c
  )
ENDIF(ENABLE_PROFILING)

IF(MONO_FOUND)
  SET(COMO_SRCS
    ${COMO_SRCS}
    ${COMO_SOURCE_DIR}/mono/proxy-mono.c
  )
  SET_SOURCE_FILES_PROPERTIES(${COMO_SOURCE_DIR}/mono/proxy-mono.c
      PROPERTIES COMPILE_FLAGS ${MONO_CFLAGS})
ENDIF(MONO_FOUND)

IF(ENABLE_LOADSHED)
  SET(COMO_SRCS
    ${COMO_SRCS}
    ${COMO_SOURCE_DIR}/loadshed/loadshed.c
    ${COMO_SOURCE_DIR}/loadshed/feats.c
    ${COMO_SOURCE_DIR}/loadshed/prediction.c
    ${COMO_SOURCE_DIR}/loadshed/ls-profiling.c
  )
ENDIF(ENABLE_LOADSHED)

#
# Create target for the filter parser
#
ADD_CUSTOM_TARGET(FilterLexic echo "Creating filter-lexic.c")
ADD_CUSTOM_TARGET(FilterSyntax echo "Creating filter-syntax.c")

ADD_CUSTOM_TARGET(ConfigLexic echo "Creating config-lexic.c")
ADD_CUSTOM_TARGET(ConfigSyntax echo "Creating config-syntax.c")

ADD_CUSTOM_TARGET(QueryLexic echo "Creating query-lexic.c")
ADD_CUSTOM_TARGET(QuerySyntax echo "Creating query-syntax.c")

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

ADD_CUSTOM_COMMAND(
	SOURCE ${COMO_SOURCE_DIR}/base/config-lexic.l
	COMMAND ${FLEX_EXECUTABLE}
	ARGS -Pyc -o${COMO_BINARY_DIR}/base/config-lexic.c
	    ${COMO_SOURCE_DIR}/base/config-lexic.l
	TARGET ConfigLexic
	OUTPUTS ${COMO_BINARY_DIR}/base/config-lexic.c
)

ADD_CUSTOM_COMMAND(
	SOURCE ${COMO_SOURCE_DIR}/base/query-lexic.l
	COMMAND ${FLEX_EXECUTABLE}
	ARGS -Pyq -o${COMO_BINARY_DIR}/base/query-lexic.c
	    ${COMO_SOURCE_DIR}/base/query-lexic.l
	TARGET QueryLexic
	OUTPUTS ${COMO_BINARY_DIR}/base/query-lexic.c
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

ADD_CUSTOM_COMMAND(
	SOURCE ${COMO_SOURCE_DIR}/base/config-syntax.y
	COMMAND ${BISON_EXECUTABLE} 
	ARGS -p yc -y ${COMO_SOURCE_DIR}/base/config-syntax.y
	    -o ${COMO_BINARY_DIR}/base/config-syntax.c
	TARGET ConfigSyntax
	DEPENDS ${COMO_BINARY_DIR}/base/config-lexic.c
	OUTPUTS ${COMO_BINARY_DIR}/base/config-syntax.c
)

ADD_CUSTOM_COMMAND(
	SOURCE ${COMO_SOURCE_DIR}/base/query-syntax.y
	COMMAND ${BISON_EXECUTABLE} 
	ARGS -p yq -y ${COMO_SOURCE_DIR}/base/query-syntax.y
	    -o ${COMO_BINARY_DIR}/base/query-syntax.c
	TARGET QuerySyntax
	DEPENDS ${COMO_BINARY_DIR}/base/query-lexic.c
	OUTPUTS ${COMO_BINARY_DIR}/base/query-syntax.c
)

#
# Add syntax files to COMO_SRCS
#
SET(COMO_SRCS ${COMO_SRCS} ${COMO_BINARY_DIR}/base/filter-syntax.c)
SET(COMO_SRCS ${COMO_SRCS} ${COMO_BINARY_DIR}/base/config-syntax.c)
SET(COMO_SRCS ${COMO_SRCS} ${COMO_BINARY_DIR}/base/query-syntax.c)

#
# Since .y and .l do not exist yet when cmake is run, mark them as generated
#
SET_SOURCE_FILES_PROPERTIES(${COMO_BINARY_DIR}/base/filter-lexic.c GENERATED)
SET_SOURCE_FILES_PROPERTIES(${COMO_BINARY_DIR}/base/config-lexic.c GENERATED)
SET_SOURCE_FILES_PROPERTIES(${COMO_BINARY_DIR}/base/filter-syntax.c GENERATED)
SET_SOURCE_FILES_PROPERTIES(${COMO_BINARY_DIR}/base/config-syntax.c GENERATED)
SET_SOURCE_FILES_PROPERTIES(${COMO_BINARY_DIR}/base/query-syntax.c GENERATED)
SET_SOURCE_FILES_PROPERTIES(${COMO_BINARY_DIR}/base/query-syntax.c GENERATED)

#
# Some versions of flex (at least 2.5.33) produce code with comparisons between
# signed and unsigned vars. This, combined with -Wall and -Werror, prevents CoMo
# from building. We add -Wno-sign-compare to gcc flags to work around this.
#
# (see bug #1468610 for the flex project at http://sf.net/projects/flex)
#
SET_SOURCE_FILES_PROPERTIES(${COMO_BINARY_DIR}/base/filter-lexic.c COMPILE_FLAGS -Wno-sign-compare)
SET_SOURCE_FILES_PROPERTIES(${COMO_BINARY_DIR}/base/filter-syntax.c COMPILE_FLAGS -Wno-sign-compare)
SET_SOURCE_FILES_PROPERTIES(${COMO_BINARY_DIR}/base/config-lexic.c COMPILE_FLAGS -Wno-sign-compare)
SET_SOURCE_FILES_PROPERTIES(${COMO_BINARY_DIR}/base/config-syntax.c COMPILE_FLAGS -Wno-sign-compare)
SET_SOURCE_FILES_PROPERTIES(${COMO_BINARY_DIR}/base/query-lexic.c COMPILE_FLAGS -Wno-sign-compare)
SET_SOURCE_FILES_PROPERTIES(${COMO_BINARY_DIR}/base/query-syntax.c COMPILE_FLAGS -Wno-sign-compare)

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

ADD_DEPENDENCIES(como services_library)
TARGET_LINK_LIBRARIES(como ${COMO_BINARY_DIR}/services/libservices.a)

TARGET_LINK_LIBRARIES(como m)

TARGET_LINK_LIBRARIES(como comomdl)

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

IF(MONO_FOUND)
  TARGET_LINK_LIBRARIES(como ${MONO_LIBS})
ENDIF(MONO_FOUND)

TARGET_LINK_LIBRARIES(como ${APR_LIBS})

#
# Installation
#
INSTALL_TARGETS(${INST_BINDIR} como)

