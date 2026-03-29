# Copyright (C) Pavel Grebnev 2026
# Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

cmake_minimum_required(VERSION 3.22.1)

include(CTest)
include(GoogleTest)

set(TESTS_ROOT ${CMAKE_CURRENT_LIST_DIR})

set(TESTS_SRC_DIR ${TESTS_ROOT}/src)

add_executable(Tests)

if(MSVC)
	target_compile_options(Tests PRIVATE /W4 /WX)
else()
	target_compile_options(Tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

target_include_directories(Tests PRIVATE
	${TESTS_ROOT}/include
	${MAIN_ROOT}/CommonShared/include
	${TESTS_ROOT}/deps/googletest/googletest
	${TESTS_ROOT}/deps/googletest/googletest/include
)

file(GLOB_RECURSE TESTS_SRC_LIST RELATIVE "" FOLLOW_SYMLINKS "${TESTS_SRC_DIR}/*")

target_sources(Tests PRIVATE
	${TESTS_SRC_LIST}
	${TESTS_ROOT}/deps/googletest/googletest/src/gtest-all.cc
)

target_link_libraries(Tests
	PRIVATE
		CommonShared
)

gtest_discover_tests(Tests)

add_custom_command(TARGET Tests
	COMMENT "Run tests"
	POST_BUILD
	COMMAND ${CMAKE_CTEST_COMMAND} --stop-on-failure --output-on-failure
)
