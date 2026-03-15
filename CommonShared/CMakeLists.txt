# Copyright (C) Pavel Grebnev 2026
# Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

cmake_minimum_required(VERSION 3.22.1)

# needed to configure Noise-C below
include(ExternalProject)

set(COMMON_SHARED_ROOT ${CMAKE_CURRENT_LIST_DIR})

set(COMMON_SHARED_INCLUDE_BASE_DIR ${COMMON_SHARED_ROOT}/include)
set(COMMON_SHARED_INCLUDE_DIR ${COMMON_SHARED_INCLUDE_BASE_DIR}/common_shared)
set(COMMON_SHARED_SRC_DIR ${COMMON_SHARED_ROOT}/src)

# Noise-C stuff begin
find_program(AUTORECONF_EXECUTABLE autoreconf)
find_program(BISON_EXECUTABLE bison)
find_program(FLEX_EXECUTABLE flex)

if(NOT AUTORECONF_EXECUTABLE)
	message(FATAL_ERROR "autoreconf not found, it is required to build Noise-C")
endif()

if(NOT BISON_EXECUTABLE)
	message(FATAL_ERROR "bison not found, it is required to build Noise-C")
endif()

if(NOT FLEX_EXECUTABLE)
	message(FATAL_ERROR "flex not found, it is required to build Noise-C")
endif()

ExternalProject_Add(NoiseC
	SOURCE_DIR ${COMMON_SHARED_ROOT}/deps/noise-c
	DOWNLOAD_COMMAND ""
	CONFIGURE_COMMAND
		${AUTORECONF_EXECUTABLE} -i
		COMMAND ./configure --disable-shared --enable-static
	BUILD_COMMAND make
	INSTALL_COMMAND ""
	BUILD_IN_SOURCE ON
)
# Noise-C stuff end

add_library(CommonShared STATIC)

if(MSVC)
	target_compile_options(CommonShared PRIVATE /W4 /WX)
else()
	target_compile_options(CommonShared PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

target_include_directories(CommonShared PRIVATE
	${COMMON_SHARED_INCLUDE_BASE_DIR}
	${MAIN_ROOT}/deps/noise-c/include
)

target_sources(CommonShared
	PRIVATE
		${COMMON_SHARED_SRC_DIR}/debug/assert.cpp
		${COMMON_SHARED_SRC_DIR}/debug/log.cpp
		${COMMON_SHARED_SRC_DIR}/network/utils.cpp
		${COMMON_SHARED_SRC_DIR}/nsd/nsd_client.cpp
		${COMMON_SHARED_SRC_DIR}/nsd/nsd_server.cpp
		${COMMON_SHARED_SRC_DIR}/nsd/utils_internal.cpp
		${COMMON_SHARED_SRC_DIR}/serialization/number_serialization.cpp
		${COMMON_SHARED_SRC_DIR}/serialization/raw_data_serialization.cpp
		${COMMON_SHARED_SRC_DIR}/serialization/string_serialization.cpp
		${COMMON_SHARED_INCLUDE_DIR}/nsd/utils_internal.h

	PUBLIC
		${COMMON_SHARED_INCLUDE_DIR}/debug/assert.h
		${COMMON_SHARED_INCLUDE_DIR}/debug/log.h
		${COMMON_SHARED_INCLUDE_DIR}/network/utils.h
		${COMMON_SHARED_INCLUDE_DIR}/network/protocol.h
		${COMMON_SHARED_INCLUDE_DIR}/nsd/nsd_client.h
		${COMMON_SHARED_INCLUDE_DIR}/nsd/nsd_server.h
		${COMMON_SHARED_INCLUDE_DIR}/serialization/number_serialization.h
		${COMMON_SHARED_INCLUDE_DIR}/serialization/raw_data_serialization.h
		${COMMON_SHARED_INCLUDE_DIR}/serialization/string_serialization.h
)

target_link_libraries(CommonShared
	PRIVATE
		${COMMON_SHARED_ROOT}/deps/noise-c/src/keys/libnoisekeys.a
		${COMMON_SHARED_ROOT}/deps/noise-c/src/protocol/libnoiseprotocol.a
		${COMMON_SHARED_ROOT}/deps/noise-c/src/protobufs/libnoiseprotobufs.a
)
