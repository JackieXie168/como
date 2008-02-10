#
# Enable cross compilation for ARM architecture
#

MACRO(COMO_BUILD_FOR_ARM)
  MESSAGE(STATUS "Cross compiling for ARM")
  SET(CMAKE_C_COMPILER "arm-linux-gcc")
  SET(CMAKE_COMPILER_IS_GNUCC 1)
  SET(CMAKE_AR "arm-linux-ar")
  SET(CMAKE_RANLIB "arm-linux-ranlib")
  ADD_DEFINITIONS(-DBUILD_FOR_ARM)
ENDMACRO(COMO_BUILD_FOR_ARM)
