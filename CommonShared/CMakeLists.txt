# Copyright (C) Pavel Grebnev 2026
# Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

cmake_minimum_required(VERSION 3.28)

set(COMMON_SHARED_ROOT ${CMAKE_SOURCE_DIR}/CommonShared)

set(COMMON_SHARED_INCLUDE_BASE_DIR ${COMMON_SHARED_ROOT}/include)
set(COMMON_SHARED_INCLUDE_DIR ${COMMON_SHARED_INCLUDE_BASE_DIR}/common_shared)
set(COMMON_SHARED_SRC_DIR ${COMMON_SHARED_ROOT}/src)

add_library(CommonShared STATIC)

target_sources(CommonShared
	PRIVATE
		${COMMON_SHARED_SRC_DIR}/debug/log.cpp

	PUBLIC
    FILE_SET headers
    TYPE HEADERS
    BASE_DIRS
		${COMMON_SHARED_INCLUDE_BASE_DIR}
    FILES
		${COMMON_SHARED_INCLUDE_DIR}/debug/log.h
)
