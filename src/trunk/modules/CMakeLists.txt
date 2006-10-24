INCLUDE_DIRECTORIES(${COMO_SOURCE_DIR}/include)

SET(MODULES
  apps
  assoc
  dhcp
  ethtypes
  ewma
  flowcount
  frames
  ipssi
  macssi
  nfexlist
  pattern-search
  protocol
  ssid
  topaddr
  tophwaddr
  topports
  trace
  traffic
  traffic-matrix
  tuple
  unknown-ports
)

IF(FTLIB_FOUND)
  SET(MODULES
    ${MODULES}
    netflow-anon
  )
ENDIF(FTLIB_FOUND)

IF(ENABLE_SHARED_MODULES)
  FOREACH(module ${MODULES})
    ADD_LIBRARY(${module} SHARED ${module}.c)
    # Get rid of the 'lib' prefix for modules
    SET_TARGET_PROPERTIES(${module}
      PROPERTIES
      PREFIX ""
    )
    INSTALL_TARGETS(${INST_LIBDIR} ${module})
  ENDFOREACH(module)
ELSE(ENABLE_SHARED_MODULES)
  #
  # Write modules-list.h
  #
  SET(MODULES_LIST ${COMO_BINARY_DIR}/include/modules-list.h)
  WRITE_FILE(${MODULES_LIST}
"/* generated file, do not edit */

typedef struct builtin_module {
    const char *	name;
    module_cb_t *	cb;
} builtin_module_t;

")

  FOREACH(module ${MODULES})
    # Replace - with _ in the C module name
    STRING(REPLACE "-" "_" _cmodule ${module})
    WRITE_FILE(${MODULES_LIST}
"extern module_cb_t g_${_cmodule}_module;" APPEND)
  ENDFOREACH(module)

  WRITE_FILE(${MODULES_LIST}
"builtin_module_t g_como_builtin_modules[] = {" APPEND)

  FOREACH(module ${MODULES})
    # Replace - with _ in the C module name
    STRING(REPLACE "-" "_" _cmodule ${module})
    WRITE_FILE(${MODULES_LIST}
"    { \"${module}\", &g_${_cmodule}_module }," APPEND)
  ENDFOREACH(module)

  WRITE_FILE(${MODULES_LIST}
"    { NULL, NULL } };" APPEND)

  ADD_LIBRARY(modules STATIC ${MODULES})

ENDIF(ENABLE_SHARED_MODULES)
