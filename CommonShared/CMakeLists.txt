# Copyright (C) Pavel Grebnev 2026
# Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

cmake_minimum_required(VERSION 3.22.1)

set(COMMON_SHARED_ROOT ${CMAKE_CURRENT_LIST_DIR})

set(COMMON_SHARED_INCLUDE_BASE_DIR ${COMMON_SHARED_ROOT}/include)
set(COMMON_SHARED_INCLUDE_DIR ${COMMON_SHARED_INCLUDE_BASE_DIR}/common_shared)
set(COMMON_SHARED_SRC_DIR ${COMMON_SHARED_ROOT}/src)

# set monocypher into a separate library so it doesn't use the same compiler flags
set(MONOCYPHER_ROOT ${COMMON_SHARED_ROOT}/deps/monocypher-4.0.2)
add_library(Monocypher STATIC)
target_sources(Monocypher PRIVATE ${MONOCYPHER_ROOT}/src/monocypher.c)
target_include_directories(Monocypher PRIVATE ${MONOCYPHER_ROOT}/src)

add_library(CommonShared STATIC)

if(MSVC)
	target_compile_options(CommonShared PRIVATE /W4 /WX)
else()
	target_compile_options(CommonShared PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

target_include_directories(CommonShared PRIVATE
	${COMMON_SHARED_INCLUDE_BASE_DIR}
	${MONOCYPHER_ROOT}/src
)

target_sources(CommonShared
	PRIVATE
		${COMMON_SHARED_SRC_DIR}/cryptography/primitives/cipher_functions.cpp
		${COMMON_SHARED_SRC_DIR}/cryptography/primitives/dh_functions.cpp
		${COMMON_SHARED_SRC_DIR}/cryptography/primitives/hash_functions.cpp
		${COMMON_SHARED_SRC_DIR}/cryptography/utils/erasable_data.cpp
		${COMMON_SHARED_SRC_DIR}/cryptography/utils/random.cpp
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
		${COMMON_SHARED_INCLUDE_DIR}/cryptography/primitives/cipher_functions.h
		${COMMON_SHARED_INCLUDE_DIR}/cryptography/primitives/dh_functions.h
		${COMMON_SHARED_INCLUDE_DIR}/cryptography/primitives/hash_functions.h
		${COMMON_SHARED_INCLUDE_DIR}/cryptography/types/cipher_types.h
		${COMMON_SHARED_INCLUDE_DIR}/cryptography/types/dh_types.h
		${COMMON_SHARED_INCLUDE_DIR}/cryptography/types/hash_types.h
		${COMMON_SHARED_INCLUDE_DIR}/cryptography/utils/erasable_data.h
		${COMMON_SHARED_INCLUDE_DIR}/cryptography/utils/random.h
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

if(MSVC)
	set(PLATFORM_LIBRARIES ws2_32 wsock32 bcrypt)
else()
	set(PLATFORM_LIBRARIES "")
endif()

target_link_libraries(CommonShared
	PRIVATE
		Monocypher
		${PLATFORM_LIBRARIES}

)
