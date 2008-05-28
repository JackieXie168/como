#!/bin/sh
#
# Builds all the modules in the modules directory, using the build directory
# passed as the first argument. CoMo must be already installed in the system.
#

MODULES="autofocus ethtypes flowcount protocol topaddr topaddr_csharp tophwaddr topports trace traffic traffic_csharp tuple"

if [ $# != 2 ]
then
    echo "Usage: $0 build_directory (build|install)"
    exit -1
fi

BUILD_DIR=$1
ACTION=$2

if [ \! -d $BUILD_DIR ]
then
    echo "Error: build directory \`$BUILD_DIR' does not exist."
    echo "Build and install CoMo before compiling the modules."
    exit -1
fi

for MODULE in $MODULES
do
    MODULE_BUILD_DIR="$BUILD_DIR/modules/$MODULE"
    MODULE_SRC_DIR="modules/$MODULE"

    echo "Building module $MODULE"
    mkdir -p "$MODULE_BUILD_DIR" ||
        { echo "Error creating $MODULE_BUILD_DIR" ; exit -1; }
    
    como_module.sh $ACTION $MODULE $MODULE_SRC_DIR $MODULE_BUILD_DIR ||
        { echo "Error building $MODULE"; exit -1; }
done
