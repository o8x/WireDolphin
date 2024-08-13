#!/usr/bin/env bash

CMAKE_BUILD_DIR="cmake-build-release"

hack/makeicns.sh
cmake -G Ninja -S $(pwd) -B ${CMAKE_BUILD_DIR} \
	-DCMAKE_BUILD_TYPE=Release \
	-DCMAKE_MAKE_PROGRAM=`which ninja` \
	-DCMAKE_TOOLCHAIN_FILE=${VCPKG_ROOT:-'~/vcpkg'}/scripts/buildsystems/vcpkg.cmake

cmake --build ${CMAKE_BUILD_DIR} --target all -j `nproc`

cd ${CMAKE_BUILD_DIR}
macdeployqt6 *.app -dmg
cd ..

mv ${CMAKE_BUILD_DIR}/*.dmg .
rm -rf ${CMAKE_BUILD_DIR}
