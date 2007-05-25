INCLUDE_DIRECTORIES(${COMO_SOURCE_DIR}/include)

IF(ENABLE_LOADSHED)
  INCLUDE_DIRECTORIES(${COMO_SOURCE_DIR}/loadshed)
ENDIF(ENABLE_LOADSHED)

SET(SERVICES
  status
#  trace
)

#
# Write services-list.h
#
SET(SERVICES_LIST ${COMO_BINARY_DIR}/include/services-list.h)
WRITE_FILE(${SERVICES_LIST}
"/* generated file, do not edit */

typedef struct builtin_service {
    const char *	name;
    service_fn		service;
} builtin_service_t;

")

FOREACH(service ${SERVICES})
  # Replace - with _ in the C service name
  STRING(REPLACE "-" "_" _cservice ${service})
  WRITE_FILE(${SERVICES_LIST}
"extern int service_${_cservice}(int client_fd, como_node_t * node, qreq_t * qreq);" APPEND)
ENDFOREACH(service)

WRITE_FILE(${SERVICES_LIST}
"builtin_service_t g_como_builtin_services[] = {" APPEND)

FOREACH(service ${SERVICES})
  # Replace - with _ in the C service name
  STRING(REPLACE "-" "_" _cservice ${service})
  WRITE_FILE(${SERVICES_LIST}
"    { \"${service}\", service_${_cservice} }," APPEND)
ENDFOREACH(service)

WRITE_FILE(${SERVICES_LIST}
"    { NULL, NULL } };" APPEND)

ADD_LIBRARY(services STATIC ${SERVICES})

# create a 'services_library' target that base can depend on
ADD_CUSTOM_TARGET(services_library)
ADD_DEPENDENCIES(services_library services)

