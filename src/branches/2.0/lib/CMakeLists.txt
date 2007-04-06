INCLUDE_DIRECTORIES(${COMO_SOURCE_DIR}/include)

SET(COMOMDL_SRCS
  flowtable.c
  uhash.c
  printpkt.c
  protoname.c
)

ADD_LIBRARY(comomdl STATIC ${COMOMDL_SRCS})
ADD_CUSTOM_TARGET(modules_library)
ADD_DEPENDENCIES(modules_library comomdl)
