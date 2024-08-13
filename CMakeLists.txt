cmake_minimum_required(VERSION 3.29)

set(CMAKE_PROJECT_NAME WireDolphin)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(QT_VERSION 6.7.2)
# CMAKE_PREFIX_PATH 效果一致，但会出现一些警告
set(Qt6_DIR $ENV{HOME}/Qt6/${QT_VERSION}/macos/lib/cmake/Qt6)

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
        include/logger.h
        src/packet/packetsource.cpp
        src/utils/utils.cpp
        src/packet/packet.cpp
        src/window/mainwindow.cpp
        src/window/mainwindow.ui
        src/interface.cpp
        src/dissectors/ipv4.cpp
        src/dissectors/ipv6.cpp
        src/logger/logger.cpp
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
)

find_package(Qt6 COMPONENTS Core Gui Widgets Charts REQUIRED)
target_link_libraries(${PROJECT_NAME} PRIVATE Qt::Core Qt::Gui Qt::Charts Qt::Widgets pcap)
target_link_directories(${PROJECT_NAME} PRIVATE /opt/homebrew/opt/libpcap/lib)
target_include_directories(${PROJECT_NAME} PRIVATE /opt/homebrew/opt/libpcap/include)

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

set(CMAKE_AUTORCC ON)
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_CURRENT_SOURCE_DIR}/resources/icon.icns"
        "$<TARGET_BUNDLE_DIR:${PROJECT_NAME}>/Contents/Resources/icon.icns"
)

set(CLI_PROJECT_NAME ${PROJECT_NAME}-cli)
add_executable(${CLI_PROJECT_NAME}
        src/interface.cpp
        include/interface.h
        include/logger.h
        src/logger/logger.cpp
        cli.cpp
)

target_link_libraries(${CLI_PROJECT_NAME} PRIVATE pcap)
target_link_directories(${CLI_PROJECT_NAME} PRIVATE /opt/homebrew/opt/libpcap/lib)
target_include_directories(${CLI_PROJECT_NAME} PRIVATE /opt/homebrew/opt/libpcap/include)
