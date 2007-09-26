# $Id$

INCLUDE_DIRECTORIES(${COMO_SOURCE_DIR}/include)

IF(ENABLE_LOADSHED)
  INCLUDE_DIRECTORIES(${COMO_SOURCE_DIR}/loadshed)
ENDIF(ENABLE_LOADSHED)

SET(COMOMDL_SRCS
  flowtable.c
  uhash.c
  printpkt.c
  protoname.c
  bitmap.c
)

ADD_LIBRARY(comomdl STATIC ${COMOMDL_SRCS})
ADD_CUSTOM_TARGET(modules_library)
ADD_DEPENDENCIES(modules_library comomdl)
