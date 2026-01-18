# Copyright (C) Pavel Grebnev 2026
# Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

cmake_minimum_required(VERSION 3.22.1)

set(SERVER_SHARED_ROOT ${CMAKE_CURRENT_LIST_DIR})

set(SERVER_SHARED_INCLUDE_BASE_DIR ${SERVER_SHARED_ROOT}/include)
set(SERVER_SHARED_INCLUDE_DIR ${SERVER_SHARED_INCLUDE_BASE_DIR}/server_shared)
set(SERVER_SHARED_SRC_DIR ${SERVER_SHARED_ROOT}/src)

add_library(ServerShared STATIC)

target_include_directories(ServerShared PRIVATE
	${MAIN_ROOT}/CommonShared/include
	${SERVER_SHARED_INCLUDE_BASE_DIR}
)

target_sources(ServerShared
	PRIVATE
		${SERVER_SHARED_SRC_DIR}/example/example.cpp

	PUBLIC
		${SERVER_SHARED_INCLUDE_DIR}/example/example.h
)
