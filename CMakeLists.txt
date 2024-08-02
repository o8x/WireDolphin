cmake_minimum_required(VERSION 3.29)
project(wiredolphin)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 COMPONENTS Core Gui Widgets REQUIRED)

add_executable(wiredolphin
        main.cpp
        include/packetsource.h
        include/utils.h
        include/Packet.h
        include/mainwindow.h
        include/interface.h
        include/protocol.h
        src/packetsource.cpp
        src/utils/utils.cpp
        src/packet.cpp
        src/mainwindow.cpp
        src/mainwindow.ui
        src/interface.cpp
)

include_directories(include)
target_link_libraries(wiredolphin PRIVATE Qt::Core Qt::Gui Qt::Widgets pcap)
target_link_directories(wiredolphin PRIVATE /opt/homebrew/opt/libpcap/lib)
target_include_directories(wiredolphin PRIVATE /opt/homebrew/opt/libpcap/include)

set_target_properties(wiredolphin PROPERTIES OUTPUT_NAME wiredolphin INSTALL_PATH "./libs")

add_executable(wiredolphin-cli
        src/interface.cpp
        include/interface.h
        cli.cpp
)

target_link_libraries(wiredolphin-cli PRIVATE pcap)
target_link_directories(wiredolphin-cli PRIVATE /opt/homebrew/opt/libpcap/lib)
target_include_directories(wiredolphin-cli PRIVATE /opt/homebrew/opt/libpcap/include)

qt_finalize_executable(wiredolphin)

include(GNUInstallDirs)
install(PROGRAMS $<TARGET_FILE:wiredolphin> TYPE BIN)
install(DIRECTORY "${CMAKE_BINARY_DIR}/qtDeploy/" TYPE BIN)
set(CPACK_GENERATOR "ZIP;DMG")

include(CPack)
