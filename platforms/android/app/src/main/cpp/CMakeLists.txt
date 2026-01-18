cmake_minimum_required(VERSION 3.22.1)

project(EasyPhotoBackupFfi)

set(MAIN_ROOT ${CMAKE_CURRENT_LIST_DIR}/../../../../../..)

include(${MAIN_ROOT}/CommonShared/CMakeLists.txt)
include(${MAIN_ROOT}/ClientShared/CMakeLists.txt)

# In this top level CMakeLists.txt, ${CMAKE_PROJECT_NAME} is used to define
# the target library name; in the sub-module's CMakeLists.txt, ${PROJECT_NAME}
# is preferred for the same purpose.
#
# In order to load a library into your app from Java/Kotlin, you must call
# System.loadLibrary() and pass the name of the library defined here;
# for GameActivity/NativeActivity derived applications, the same library name must be
# used in the AndroidManifest.xml file.
add_library(${CMAKE_PROJECT_NAME} SHARED
	ffi_bindings.cpp
)

target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
	${MAIN_ROOT}/CommonShared/include
	${MAIN_ROOT}/ClientShared/include
)

target_sources(${CMAKE_PROJECT_NAME} PRIVATE
	ffi_bindings.cpp
)

target_link_libraries(${CMAKE_PROJECT_NAME}
	android
	log
	CommonShared
	ClientShared
)
