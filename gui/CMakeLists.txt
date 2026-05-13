cmake_minimum_required(VERSION 3.16)

project(ShadowIDS_GUI)
set(PROJECT_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/..)
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/../src)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets)

qt_standard_project_setup()

qt_add_executable(ShadowIDS_GUI
    main_gui.cpp
    MainWindow.cpp
    MainWindow.h

    ${SRC_DIR}/AttackAnalyzer.cpp
    ${SRC_DIR}/AttackAnalyzer.h
    ${SRC_DIR}/LogList.cpp
    ${SRC_DIR}/LogList.h
    ${SRC_DIR}/LogNode.h
    ${SRC_DIR}/CustomQueue.h
)

target_include_directories(ShadowIDS_GUI PRIVATE
    ${SRC_DIR}
)

target_link_libraries(ShadowIDS_GUI PRIVATE
    Qt6::Widgets
)
