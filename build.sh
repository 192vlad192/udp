#!/bin/bash

pass_for_build="./build/CMake"

cmake CMakeLists.txt -B ${pass_for_build}
if [ "$?" -eq "0" ]
then
    cd ${pass_for_build}
    make
    if [ "$?" -eq "0" ]
    then
        cd ../../
    else 
        echo -e "\033[41m\033[30m build_install: ошибка \"make\" \033[0m"
    fi
else
    echo -e "\033[41m\033[30m build_install: ошибка \"cmake CMakeLists\" \033[0m"
fi