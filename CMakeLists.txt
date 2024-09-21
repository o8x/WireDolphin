cmake_minimum_required(VERSION 3.28.6)

set(CMAKE_PROJECT_NAME WireDolphin)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_VERBOSE_MAKEFILE ON)
# 生成编译数据库文件，Fleet 等编译器需要该文件
# 直接生成 cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON .
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# 无法自动加载时，设置 QT 目录
#set(Qt6_DIR $ENV{HOME}/Qt6/6.7.2/macos/lib/cmake/Qt6)

project(WireDolphin VERSION 0.1.0 LANGUAGES CXX)

include_directories(include)
add_executable(${PROJECT_NAME}
        main.cpp
        include/packetsource.h
        include/utils.h
        include/Packet.h
        include/mainwindow.h
        include/interface.h
        include/dissectors/ipv4.h
        include/dissectors/ipv6.h
        include/dissectors/ethernet.h
        src/packet/packetsource.cpp
        src/utils/utils.cpp
        src/packet/packet.cpp
        src/window/mainwindow.cpp
        src/window/mainwindow.ui
        src/interface.cpp
        src/dissectors/ipv4.cpp
        src/dissectors/ipv6.cpp
        src/dissectors/tcp.cpp
        include/dissectors/tcp.h
        include/dissectors/arp.h
        src/dissectors/arp.cpp
        src/dissectors/udp.cpp
        include/dissectors/udp.h
        include/dissectors/http.h
        src/dissectors/http.cpp
        include/statswindow.h
        src/window/stats/statswindow.cpp
        src/window/stats/statswindow.ui
        src/qcustomplot.cpp
        include/qcustomplot.h
        src/axistag.cpp
        include/axistag.h
        include/trayicon.h
        src/trayicon.cpp
        include/conf.h
        src/conf.cpp
        include/dissectors/icmp.h
        src/dissectors/icmp.cpp
)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions(-DDEBUG_BUILD)
endif ()

if (CMAKE_BUILD_TYPE STREQUAL "Release")
    # 为 release 模式设置优化选型
    # -O3：开启最高级别的优化
    # -march=native：针对构建机器的本地架构进行优化（这可能会生成仅在类似机器上运行良好的代码）
    # -ffast-math：允许编译器在浮点数运算中使用可能违反 IEEE 标准的优化，能显著提高执行速度，但可能会破坏浮点数的精确度或兼容性
    # -DNDEBUG：定义 NDEBUG 宏，这通常会关闭 assert() 语句（如果你在使用它们的话）
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -march=native -ffast-math -DNDEBUG")
endif ()

# qt core
find_package(Qt6 COMPONENTS Core Gui Widgets PrintSupport REQUIRED)
target_link_libraries(${PROJECT_NAME} PRIVATE Qt::Core Qt::Gui Qt::Widgets Qt::PrintSupport)
# glog
find_package(glog CONFIG REQUIRED)
target_link_libraries(${PROJECT_NAME} PRIVATE glog::glog)

# libpcap
find_package(PkgConfig REQUIRED)
pkg_check_modules(VCPKG_DEPS REQUIRED libpcap tinyxml2)
target_link_libraries(${PROJECT_NAME} PRIVATE ${VCPKG_DEPS_LIBRARIES})
target_link_directories(${PROJECT_NAME} PRIVATE ${VCPKG_DEPS_LIBRARY_DIRS})
target_include_directories(${PROJECT_NAME} PRIVATE ${VCPKG_DEPS_INCLUDE_DIRS})

set_target_properties(${PROJECT_NAME} PROPERTIES
        ${BUNDLE_ID_OPTION}
        MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
        MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
        MACOSX_BUNDLE TRUE
        WIN32_EXECUTABLE TRUE
)

include(GNUInstallDirs)
qt_finalize_executable(${PROJECT_NAME})
install(TARGETS ${PROJECT_NAME}
        BUNDLE DESTINATION .
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_CURRENT_SOURCE_DIR}/resources/icon.icns"
        "$<TARGET_BUNDLE_DIR:${PROJECT_NAME}>/Contents/Resources/icon.icns"
)

add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory
        "$<TARGET_BUNDLE_DIR:${PROJECT_NAME}>/Contents/logs"
)
