INCLUDE_DIRECTORIES(${COMO_SOURCE_DIR}/include)
INCLUDE_DIRECTORIES(${COMO_SOURCE_DIR}/base)

#
# Sniffers always compiled
#
SET(SNIFFERS
  pcap
  como
  #ondemand
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
#  IF(FTLIB_FOUND)
#    SET(SNIFFERS
#      ${SNIFFERS}
#      flowtools
#      netflow
#    )
#    INCLUDE_DIRECTORIES(${FTLIB_INCLUDE_DIR})
#  ENDIF(FTLIB_FOUND)

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
#IF(LINUX)
#  SET(SNIFFERS
#    ${SNIFFERS}
#    radio
#  )
#ENDIF(LINUX)

#
# Sniffers specific to FreeBSD
#
#IF(FREEBSD)
#  SET(SNIFFERS
#    ${SNIFFERS}
#    bpf
#  )
#ENDIF(FREEBSD)

#
# Write sniffers-list.h
#
SET(SNIFFER_LIST ${COMO_BINARY_DIR}/include/sniffers-list.h)
WRITE_FILE(${SNIFFER_LIST} "/* generated file, do not edit */")

FOREACH(sniffer ${SNIFFERS})
  WRITE_FILE(${SNIFFER_LIST} "extern sniffer_cb_t como_${sniffer}_sniffer;" APPEND)
ENDFOREACH(sniffer)

WRITE_FILE(${SNIFFER_LIST} "sniffer_cb_t *g_como_builtin_sniffers[] = {" APPEND)

FOREACH(sniffer ${SNIFFERS})
  WRITE_FILE(${SNIFFER_LIST} "    &como_${sniffer}_sniffer," APPEND)
ENDFOREACH(sniffer)

WRITE_FILE(${SNIFFER_LIST} "    NULL };" APPEND)

#
# Add sniffer sources to SNIFFERS_SRCS
#
FOREACH(sniffer ${SNIFFERS})
  SET(SNIFFERS_SRCS ${SNIFFERS_SRCS} sniffer-${sniffer}.c)
ENDFOREACH(sniffer)

ADD_LIBRARY(sniffers STATIC ${SNIFFERS_SRCS})
