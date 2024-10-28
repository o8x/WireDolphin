#!/usr/bin/env bash

set -ex

CMAKE_BUILD_DIR="cmake-build-release"

hack/makeicns.sh
cmake -G Ninja -S $(pwd) -B ${CMAKE_BUILD_DIR} \
	-DCMAKE_BUILD_TYPE=Release \
	-DCMAKE_MAKE_PROGRAM=`which ninja` \
	-DCMAKE_TOOLCHAIN_FILE=${VCPKG_ROOT:-'~/vcpkg'}/scripts/buildsystems/vcpkg.cmake

cmake --build ${CMAKE_BUILD_DIR} --target all -j `nproc`

cd ${CMAKE_BUILD_DIR}
APP_NAME=$(cd *.app ; echo $(basename $(pwd)))

# 先让 qt 拷贝链接库到 .app 中
macdeployqt6 $APP_NAME -dmg

# 创建自有的 CA，非必需
# https://developer.apple.com/help/account/create-certificates/create-a-certificate-signing-request
# 不签名无法在开启了 SIP 的系统中运行
# https://github.com/orgs/Homebrew/discussions/3088
# https://forum.qt.io/topic/136644/macqtdeploy-cmake-arm-m1-to-intel-oh-dear
# 此时为 .app 签名时，已经包含了 qt 拷贝的文件
codesign --verify --verbose --force --deep -s - $APP_NAME
codesign --verify --verbose $APP_NAME

# 重新为具备完整签名的 .app 生成 dmg
rm -f *.dmg
macdeployqt6 $APP_NAME -dmg
spctl -a -t open --context context:primary-signature -v *.dmg

cd ..
mv ${CMAKE_BUILD_DIR}/*.dmg .
rm -rf ${CMAKE_BUILD_DIR}

echo -e "use Console.app to watch WireDolphin Log"
