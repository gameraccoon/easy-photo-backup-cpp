# Copyright (C) Pavel Grebnev 2026
# Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

cmake_minimum_required(VERSION 3.22.1)

set(SERVER_CLI_ROOT ${CMAKE_SOURCE_DIR}/ServerCli)

set(SERVER_CLI_SRC_DIR ${SERVER_CLI_ROOT}/src)

add_executable(ServerCli)

target_include_directories(ServerCli PRIVATE
	CommonShared/include
	ClientShared/include
)

target_sources(ServerCli PRIVATE
	${SERVER_CLI_SRC_DIR}/main.cpp
)

target_link_libraries(ServerCli
	PRIVATE
		CommonShared
		ServerShared
)
