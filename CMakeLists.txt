cmake_minimum_required(VERSION 3.29)
project(wiredolphin)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(untitled VERSION 0.1 LANGUAGES CXX)

include_directories(include)
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

find_package(Qt6 COMPONENTS Core Gui Widgets REQUIRED)
target_link_libraries(wiredolphin PRIVATE Qt::Core Qt::Gui Qt::Widgets pcap)
target_link_directories(wiredolphin PRIVATE /opt/homebrew/opt/libpcap/lib)
target_include_directories(wiredolphin PRIVATE /opt/homebrew/opt/libpcap/include)

set_target_properties(wiredolphin PROPERTIES
        ${BUNDLE_ID_OPTION}
        MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
        MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
        MACOSX_BUNDLE TRUE
        WIN32_EXECUTABLE TRUE
)

include(GNUInstallDirs)
qt_finalize_executable(wiredolphin)
install(TARGETS wiredolphin
        BUNDLE DESTINATION .
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

add_executable(wiredolphin-cli
        src/interface.cpp
        include/interface.h
        cli.cpp
)

target_link_libraries(wiredolphin-cli PRIVATE pcap)
target_link_directories(wiredolphin-cli PRIVATE /opt/homebrew/opt/libpcap/lib)
target_include_directories(wiredolphin-cli PRIVATE /opt/homebrew/opt/libpcap/include)
