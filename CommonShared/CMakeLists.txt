# Copyright (C) Pavel Grebnev 2026
# Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

cmake_minimum_required(VERSION 3.22.1)

set(COMMON_SHARED_ROOT ${CMAKE_CURRENT_LIST_DIR})

set(COMMON_SHARED_INCLUDE_BASE_DIR ${COMMON_SHARED_ROOT}/include)
set(COMMON_SHARED_INCLUDE_DIR ${COMMON_SHARED_INCLUDE_BASE_DIR}/common_shared)
set(COMMON_SHARED_SRC_DIR ${COMMON_SHARED_ROOT}/src)

add_subdirectory(${COMMON_SHARED_ROOT}/deps/mbedtls ${COMMON_SHARED_ROOT}/build/mdebtls)

add_library(CommonShared STATIC)

target_include_directories(CommonShared PRIVATE
	${COMMON_SHARED_INCLUDE_BASE_DIR}
	${MAIN_ROOT}/deps/mbedtls/include
)

target_sources(CommonShared
	PRIVATE
		${COMMON_SHARED_SRC_DIR}/debug/log.cpp
		${COMMON_SHARED_SRC_DIR}/nsd/nsd_client.cpp
		${COMMON_SHARED_SRC_DIR}/nsd/nsd_server.cpp
		${COMMON_SHARED_SRC_DIR}/nsd/utils_internal.cpp
		${COMMON_SHARED_INCLUDE_DIR}/nsd/utils_internal.h

	PUBLIC
		${COMMON_SHARED_INCLUDE_DIR}/debug/log.h
		${COMMON_SHARED_INCLUDE_DIR}/nsd/nsd_client.h
		${COMMON_SHARED_INCLUDE_DIR}/nsd/nsd_server.h
		${COMMON_SHARED_INCLUDE_DIR}/nsd/shared_types.h
)

target_link_libraries(CommonShared
	PRIVATE
		mbedtls
)
