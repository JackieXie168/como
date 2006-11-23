INCLUDE_DIRECTORIES(${COMO_SOURCE_DIR}/include)

SET(COMOLIB_SRCS
  como.c
  log.c
  setproctitle.c
  ipc.c
  eventloop.c
  storage-client.c
  memory.c
  pool.c
  array.c
  shobj.c
  socket.c
  mdl.c
  shmem.c
  alc.c
  hash.c
  util-io.c
)

ADD_LIBRARY(comolib STATIC ${COMOLIB_SRCS})
