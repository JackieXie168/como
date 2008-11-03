#!/bin/sh
#
# Script to build como modules. CoMo must already be installed in the system.
#

CMAKELISTS="@ABS_INST_ETCDIR@/CMakeLists.txt"

ACTION=$1
MODULE=$2
MODULE_DIR=$3
BUILD_DIR=$4

USAGE="Usage: $0 (build|install) module_name [source_directory] [build_directory]"

# check for correct number of args
if [ $# -lt 2 ]
then
    echo $USAGE
    exit -1
fi

# check action is sane
if [ "$ACTION" != "build" -a "$ACTION" != "install" ]
then
    echo "Invalid action $ACTION"
    echo $USAGE
    exit -1
fi

# if no source_directory supplied, default to source_directory = module_name
if [ -z "$MODULE_DIR" ] ; then
    MODULE_DIR="$MODULE"
fi

# check the module directory is there
if [ \! -d $MODULE_DIR ] ; then
    echo "Error: module directory \`$MODULE_DIR' does not exist"
    echo $USAGE
    exit -1
fi

# if build directory supplied, check it exists. otherwise
# create the default build directory inside the source_directory
if [ -z "$BUILD_DIR" ]
then
    BUILD_DIR="$MODULE_DIR/build"
    echo "Defaulting to BUILD_DIR=$BUILD_DIR"
    mkdir -p $BUILD_DIR || exit -1
else
    if [ \! -d $BUILD_DIR ]
    then
        echo "Error: build directory \`$BUILD_DIR' does not exist"
        echo $USAGE
        exit -1
    fi
fi

# get the full paths
FULL_MODULE_DIR=`cd $MODULE_DIR && pwd`
FULL_BUILD_DIR=`cd $BUILD_DIR && pwd`

echo "Building module $MODULE"
echo "Module directory: $FULL_MODULE_DIR"
echo "Build directory:  $FULL_BUILD_DIR"

echo "Entering module dir"
cd $FULL_MODULE_DIR
echo "Copying template CMakeLists.txt"
cp $CMAKELISTS .

echo "Entering build dir"
cd $FULL_BUILD_DIR
cmake -D MODULE=$MODULE $FULL_MODULE_DIR || \
    { echo Skipping $MODULE: build dependencies not met; exit; }
echo Building module


if [ "$ACTION" != "install" ]
then
    make
else
    make install
fi


