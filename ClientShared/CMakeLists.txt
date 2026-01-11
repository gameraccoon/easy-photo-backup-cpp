# Copyright (C) Pavel Grebnev 2026
# Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

cmake_minimum_required(VERSION 3.22.1)

set(CLIENT_SHARED_ROOT ${CMAKE_SOURCE_DIR}/ClientShared)

set(CLIENT_SHARED_INCLUDE_BASE_DIR ${CLIENT_SHARED_ROOT}/include)
set(CLIENT_SHARED_INCLUDE_DIR ${CLIENT_SHARED_INCLUDE_BASE_DIR}/client_shared)
set(CLIENT_SHARED_SRC_DIR ${CLIENT_SHARED_ROOT}/src)

add_library(ClientShared STATIC)

target_include_directories(ClientShared PRIVATE
	CommonShared/include
)

target_sources(ClientShared
	PRIVATE
		${CLIENT_SHARED_SRC_DIR}/example/example.cpp

	PUBLIC
    FILE_SET headers
    TYPE HEADERS
    BASE_DIRS
		${CLIENT_SHARED_INCLUDE_BASE_DIR}
    FILES
		${CLIENT_SHARED_INCLUDE_DIR}/example/example.h
)
