#!/usr/bin/env bash

CMAKE_BUILD_DIR="cmake-build-release"

hack/makeicns.sh
cmake -G Ninja -S $(pwd) -B ${CMAKE_BUILD_DIR} \
	-DCMAKE_BUILD_TYPE=Release \
	-DCMAKE_MAKE_PROGRAM=`which ninja` \
	-DCMAKE_TOOLCHAIN_FILE=${VCPKG_ROOT:-'~/vcpkg'}/scripts/buildsystems/vcpkg.cmake

cmake --build ${CMAKE_BUILD_DIR} --target all -j `nproc`

cd ${CMAKE_BUILD_DIR}
APP_NAME=$(cd *.app ; echo $(basename $(pwd)))

# 生成证书
# https://developer.apple.com/help/account/create-certificates/create-a-certificate-signing-request
# 不签名无法在开启了 SIP 的系统中运行
codesign -s "WireDolphin" $APP_NAME || true
codesign --display --verbose=4 $APP_NAME

csrutil status
macdeployqt6 $APP_NAME -dmg
cd ..

mv ${CMAKE_BUILD_DIR}/*.dmg .
rm -rf ${CMAKE_BUILD_DIR}
