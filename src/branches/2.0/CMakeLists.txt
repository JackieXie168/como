#
# This is CoMo, and is written in C :-)
#
PROJECT(COMO C)

#
# Software version
#
SET(COMOVER 1.0)

#
# Where to look first for cmake modules, before ${CMAKE_ROOT}/Modules is checked
#
SET(CMAKE_MODULE_PATH "${COMO_SOURCE_DIR}/cmake/Modules")

#
# Detect SVN revision number if possible 
#
EXEC_PROGRAM(./comover-helper.sh ${COMO_SOURCE_DIR} OUTPUT_VARIABLE SVNREV)

IF(SVNREV)
  MESSAGE(STATUS "Building from SVN revision ${SVNREV}.")
  SET(COMO_VERSION "${COMOVER}\ \#${SVNREV}")
  SET(COMOVERFILE como-${COMOVER}-${SVNREV})
ELSE(SVNREV)
  SET(COMO_VERSION ${COMOVER})
  SET(COMOVERFILE como-${COMOVER})
ENDIF(SVNREV)

#
# Define some OS specific variables
#
INCLUDE(${COMO_SOURCE_DIR}/cmake/os.cmake)

#
# Handle CMAKE_BUILD_TYPE
#
IF(NOT CMAKE_BUILD_TYPE)
  # Default CMAKE_BUILD_TYPE is debug
  SET(CMAKE_BUILD_TYPE debug)
ENDIF(NOT CMAKE_BUILD_TYPE)

IF(CMAKE_BUILD_TYPE STREQUAL debug)
  SET(ENABLE_DEBUG "YES")
  SET(ENABLE_SHARED_MODULES "YES")
  SET(CMAKE_BUILD_TYPE_HANDLED "YES")
ENDIF(CMAKE_BUILD_TYPE STREQUAL debug)

IF(CMAKE_BUILD_TYPE STREQUAL debugfull)
  SET(ENABLE_DEBUG "YES")
  SET(ENABLE_PROFILING "YES")
  SET(CMAKE_BUILD_TYPE_HANDLED "YES")
ENDIF(CMAKE_BUILD_TYPE STREQUAL debugfull)

IF(CMAKE_BUILD_TYPE STREQUAL release)
  ADD_DEFINITIONS(-O2)
  SET(ENABLE_SHARED_MODULES "YES")
  SET(CMAKE_BUILD_TYPE_HANDLED "YES")
ENDIF(CMAKE_BUILD_TYPE STREQUAL release)

IF(CMAKE_BUILD_TYPE STREQUAL custom)
  SET(CMAKE_BUILD_TYPE_HANDLED "YES")
ENDIF(CMAKE_BUILD_TYPE STREQUAL custom)

IF(NOT CMAKE_BUILD_TYPE_HANDLED)
  MESSAGE(FATAL_ERROR "Unknown build type: ${CMAKE_BUILD_TYPE}")
ENDIF(NOT CMAKE_BUILD_TYPE_HANDLED)

IF(ENABLE_DEBUG)
  ADD_DEFINITIONS(-DDEBUG)
  ADD_DEFINITIONS(-g -W -Wall -Werror -Wshadow -Wcast-align)
ENDIF(ENABLE_DEBUG)

IF(ENABLE_PROFILING)
  ADD_DEFINITIONS(-pg)
ENDIF(ENABLE_PROFILING)

IF(BUILD_FOR_ARM)
  INCLUDE(${COMO_SOURCE_DIR}/cmake/arm.cmake)
  COMO_BUILD_FOR_ARM()
ENDIF(BUILD_FOR_ARM)



#
# Set installation directories. Note: all are relative to ${CMAKE_INSTALL_PREFIX}
#
SET(INST_BINDIR /bin)
SET(INST_LIBDIR /libexec/${COMOVERFILE})
SET(INST_DBDIR /share/${COMOVERFILE})
SET(INST_MANDIR /man/man1)
SET(INST_ETCDIR /etc/como)

SET(DEFAULT_LIBDIR ${CMAKE_INSTALL_PREFIX}${INST_LIBDIR})
SET(DEFAULT_DBDIR ${CMAKE_INSTALL_PREFIX}${INST_DBDIR})
SET(DEFAULT_CFGFILE ${CMAKE_INSTALL_PREFIX}${INST_ETCDIR}/como.conf)
SET(EXAMPLE_TRACE ${CMAKE_INSTALL_PREFIX}${INST_ETCDIR}/example-trace.pcap)

#
# Produce the default config file and add a rule to install it
#
CONFIGURE_FILE(como.conf.cmake ${COMO_BINARY_DIR}/como.conf)
IF(EXISTS ${DEFAULT_CFGFILE})
MESSAGE(STATUS "The default config file will not be installed because the file `${DEFAULT_CFGFILE}` already exists.")
ELSE(EXISTS ${DEFAULT_CFGFILE})
INSTALL_FILES(${INST_ETCDIR} FILES ${COMO_BINARY_DIR}/como.conf)
ENDIF(EXISTS ${DEFAULT_CFGFILE})

#
# Install a README.db into default db directory.
# The other purpose is to create that directory.
#
INSTALL_FILES(${INST_DBDIR} FILES README.db)

#
# Install an example trace
#
INSTALL_FILES(${INST_ETCDIR} FILES example-trace.pcap)

#
# Dependencies
#

#
# Search for bison
#
FIND_PACKAGE(BISON REQUIRED)

#
# Search for flex
#
FIND_PACKAGE(FLEX REQUIRED)

#
# Search for mono
#
FIND_PACKAGE(MONO)

#
# Search for libpcap library
#
FIND_PACKAGE(PCAP)

#
# Search for flow-tools library
#
FIND_PACKAGE(FT)
IF(FTLIB_FOUND AND FTLIB_LIBRARIES MATCHES "a$")
  # The static library requires ZLIB
  FIND_PACKAGE(ZLIB)
  IF(ZLIB_FOUND)
    SET(FTLIB_LIBRARIES ${FTLIB_LIBRARY} ${ZLIB_LIBRARIES})
    SET(FTLIB_INCLUDE_DIR ${FTLIB_INCLUDE_DIR} ${ZLIB_INCLUDE_DIR})
  ELSE(ZLIB_FOUND)
    MESSAGE(STATUS "Could not find zlib. Disabling flow-tools support as it requires zlib.")
    SET(FTLIB_FOUND "NO")
  ENDIF(ZLIB_FOUND)
ENDIF(FTLIB_FOUND AND FTLIB_LIBRARIES MATCHES "a$")

#
# Search for dag libray
#
FIND_PACKAGE(DAG)

#
# Output como-build.h and include its directory
#
CONFIGURE_FILE(como-build.h.cmake ${COMO_BINARY_DIR}/include/como-build.h)
INCLUDE_DIRECTORIES(${COMO_BINARY_DIR}/include)

IF(LINUX)
  # Next one is required to use 64bit off_t on Linux
  # See http://ac-archive.sourceforge.net/largefile/
  ADD_DEFINITIONS(-D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64)
ENDIF(LINUX)

#
# Make sure os.h is included everywhere
#
ADD_DEFINITIONS(-include ${COMO_SOURCE_DIR}/include/os.h)

#
# Add -O2 because it helps identify vars used without being initialized
#
#ADD_DEFINITIONS(-O2)

#
# Add subdirs
#
#
# If we have mono, add the appropirate support.
#
IF(MONO_FOUND)
  ADD_DEFINITIONS(-DMONO_SUPPORT)
  ADD_SUBDIRECTORY(mono)
ENDIF(MONO_FOUND)

ADD_SUBDIRECTORY(misc)
ADD_SUBDIRECTORY(modules)
ADD_SUBDIRECTORY(sniffers)
ADD_SUBDIRECTORY(base)
ADD_SUBDIRECTORY(services)
ADD_SUBDIRECTORY(libcomo)
ADD_SUBDIRECTORY(lib)
#ADD_SUBDIRECTORY(man)



#
# Output configuration messages
#
MESSAGE(STATUS "CoMo build type is `${CMAKE_BUILD_TYPE}`.")
MESSAGE(STATUS "CoMo will be installed in `${CMAKE_INSTALL_PREFIX}`.")
MESSAGE("Type `make` to build CoMo, `make install` to install CoMo.")
MESSAGE("Tip: you can get verbose output with `VERBOSE=1 make`.")
