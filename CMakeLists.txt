cmake_minimum_required(VERSION 3.27)

cmake_policy(SET CMP0069 NEW)
cmake_policy(SET CMP0091 NEW)

project(ClassInformer CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)
add_compile_definitions(__EA64__)

if (MSVC)
    add_compile_options(/Zc:__cplusplus)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
endif()

include(CheckIPOSupported)
check_ipo_supported(RESULT _ipo_supported OUTPUT _ipo_error)
if(_ipo_supported)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
else()
    message(WARNING "IPO/LTO not supported: ${_ipo_error}")
endif()

include(FetchContent)

FetchContent_Declare(ida_sdk
        GIT_REPOSITORY https://github.com/HexRaysSA/ida-sdk.git
        GIT_TAG v9.2)
FetchContent_MakeAvailable(ida_sdk)

set(IDASDK "${ida_sdk_SOURCE_DIR}/src" CACHE PATH "Path to IDA SDK")

FetchContent_Declare(ida_cmake
        GIT_REPOSITORY https://github.com/allthingsida/ida-cmake.git
        GIT_TAG main)
FetchContent_MakeAvailable(ida_cmake)

list(PREPEND CMAKE_PREFIX_PATH "${ida_cmake_SOURCE_DIR}")
find_package(idasdk REQUIRED CONFIG)

FetchContent_Declare(ida_support
        GIT_REPOSITORY https://github.com/ntqqrev/IDA_Support.git
        GIT_TAG master)
FetchContent_MakeAvailable(ida_support)

if(DEFINED VCPKG_INSTALLED_DIR AND DEFINED VCPKG_HOST_TRIPLET)
    set(_VCPKG_HOST_PREFIX "${VCPKG_INSTALLED_DIR}/${VCPKG_HOST_TRIPLET}")
    list(PREPEND CMAKE_PREFIX_PATH "${_VCPKG_HOST_PREFIX}")
    set(Qt6_DIR "${_VCPKG_HOST_PREFIX}/share/Qt6")
endif()
find_package(Qt6 6.8 CONFIG REQUIRED COMPONENTS Core Gui Widgets)

find_package(libxmp CONFIG REQUIRED)
set(VCPKG_APPLOCAL_DEPS OFF CACHE BOOL "" FORCE)

set(SRCS
        Main.cpp
        MainDialog.cpp
        RTTI.cpp
        Vftable.cpp
        dialog.ui
        ClassInformerRes.qrc
)

ida_add_plugin(ClassInformer
        SOURCES ${SRCS}
)

if (MSVC)
    set_property(TARGET ClassInformer PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
endif ()

set_target_properties(ClassInformer PROPERTIES
        OUTPUT_NAME "IDA_ClassInformer"
        AUTOGEN_USE_QT TRUE
        POSITION_INDEPENDENT_CODE ON
)

get_target_property(_qt_core_incs     Qt6::Core    INTERFACE_INCLUDE_DIRECTORIES)
get_target_property(_qt_widgets_incs  Qt6::Widgets INTERFACE_INCLUDE_DIRECTORIES)
target_include_directories(ClassInformer PRIVATE
        ${_qt_core_incs} ${_qt_widgets_incs}
)

option(USE_MATERIAL_DESIGN_STYLE "Build with WaitBoxEx material design variant" ON)
if(USE_MATERIAL_DESIGN_STYLE)
    target_compile_definitions(ClassInformer PRIVATE MATERIAL_DESIGN_STYLE)
    set(_WAITBOX_TARGET WaitBoxExMd)
else()
    set(_WAITBOX_TARGET WaitBoxEx)
endif()

target_link_libraries(ClassInformer PRIVATE
        ${_WAITBOX_TARGET}
        IdaOggPlayer
        SegSelect
        Utility
)

target_compile_definitions(ClassInformer PRIVATE QT_NAMESPACE=QT)

option(SPECIAL_EDITION "Build SPECIAL_EDITION flavor" OFF)
if(SPECIAL_EDITION)
    target_compile_definitions(ClassInformer PRIVATE SPECIAL_EDITION)
endif()

target_compile_options(ClassInformer PRIVATE
        $<$<AND:$<CONFIG:Release>,$<CXX_COMPILER_ID:MSVC>>:/O2>
        $<$<CXX_COMPILER_ID:MSVC>:/GR- /EHa>
        $<$<AND:$<CONFIG:Release>,$<CXX_COMPILER_ID:GNU,Clang,AppleClang>>:-O2>
)

if(WIN32)
    target_link_libraries(ClassInformer PRIVATE Winmm)
endif()

if(WIN32)
    set(IDA_QT_LIBDIR "${ida_sdk_SOURCE_DIR}/src/lib/x64_win_qt")
    target_link_directories(ClassInformer PRIVATE "${IDA_QT_LIBDIR}")
    target_link_libraries(ClassInformer PRIVATE Qt6Core Qt6Gui Qt6Widgets)
elseif(APPLE)
    set(IDA_QT_FRAMEWORKS "" CACHE PATH "Path to IDA's Qt Frameworks (e.g. <IDA.app>/Contents/Frameworks)")
    if(NOT IDA_QT_FRAMEWORKS)
        message(FATAL_ERROR "Set -DIDA_QT_FRAMEWORKS to <IDA.app>/Contents/Frameworks")
    endif()
    target_link_directories(ClassInformer PRIVATE "${IDA_QT_FRAMEWORKS}")
    target_link_libraries(ClassInformer PRIVATE "-framework QtCore" "-framework QtGui" "-framework QtWidgets")
elseif(UNIX)
    set(IDA_QT_LIBDIR "" CACHE PATH "Path to IDA's Qt .so directory")
    if(NOT IDA_QT_LIBDIR)
        message(FATAL_ERROR "Set -DIDA_QT_LIBDIR to the directory containing libQt6Core.so, etc.")
    endif()
    target_link_directories(ClassInformer PRIVATE "${IDA_QT_LIBDIR}")
    target_link_libraries(ClassInformer PRIVATE Qt6Core Qt6Gui Qt6Widgets)
    set_target_properties(ClassInformer PROPERTIES
            BUILD_RPATH   "${IDA_QT_LIBDIR}"
            INSTALL_RPATH "${IDA_QT_LIBDIR}"
    )
endif()

target_compile_definitions(ClassInformer PRIVATE __EA64__)
target_link_libraries(ClassInformer PRIVATE
        $<IF:$<TARGET_EXISTS:libxmp::xmp_shared>,libxmp::xmp_shared,libxmp::xmp_static>
)
target_link_options(ClassInformer PRIVATE /VERBOSE:LIB)