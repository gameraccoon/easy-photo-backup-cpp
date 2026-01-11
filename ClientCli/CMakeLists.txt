# Copyright (C) Pavel Grebnev 2026
# Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

cmake_minimum_required(VERSION 3.28)

set(CLIENT_CLI_ROOT ${CMAKE_SOURCE_DIR}/ClientCli)

set(CLIENT_CLI_SRC_DIR ${CLIENT_CLI_ROOT}/src)

add_executable(ClientCli)

target_include_directories(ClientCli PRIVATE
	CommonShared/include
	ClientShared/include
)

target_sources(ClientCli PRIVATE
	${CLIENT_CLI_SRC_DIR}/main.cpp
)

target_link_libraries(ClientCli
	PRIVATE
		CommonShared
		ClientShared
)
