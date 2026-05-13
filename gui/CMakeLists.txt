cmake_minimum_required(VERSION 3.16)

project(ShadowIDS_GUI)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets)

qt_standard_project_setup()

qt_add_executable(ShadowIDS_GUI
    main_gui.cpp
    MainWindow.cpp
    MainWindow.h
    ../CustomQueue.h
    ../CustomHashTable.h
    ../AttackAnalyzer.cpp
    ../AttackAnalyzer.h
    ../LogList.cpp
    ../LogList.h
    ../LogNode.h
)

target_link_libraries(ShadowIDS_GUI PRIVATE Qt6::Widgets)
