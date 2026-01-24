# Copyright (C) Pavel Grebnev 2026
# Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

cmake_minimum_required(VERSION 3.22.1)

set(CMAKE_CXX_STANDARD 20)
set(MAIN_ROOT ${CMAKE_CURRENT_LIST_DIR})

project(EasyPhotoBackup)

# mbedtls options
set(ENABLE_TESTING OFF CACHE INTERNAL "")
set(ENABLE_PROGRAMS OFF CACHE INTERNAL "")
set(ENABLE_ZLIB_SUPPORT OFF CACHE INTERNAL "")
set(LINK_WITH_PTHREAD OFF CACHE INTERNAL "")
set(UNSAFE_BUILD OFF CACHE INTERNAL "")
set(USE_PKCS11_HELPER_LIBRARY OFF CACHE INTERNAL "")
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE INTERNAL "")
set(INSTALL_MBEDTLS_HEADERS OFF CACHE INTERNAL "")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DMBEDTLS_CONFIG_FILE=\\\"mbedtls_config.h\\\"")

include(${MAIN_ROOT}/CommonShared/CMakeLists.txt)
include(${MAIN_ROOT}/ClientShared/CMakeLists.txt)
include(${MAIN_ROOT}/ServerShared/CMakeLists.txt)
include(${MAIN_ROOT}/ClientCli/CMakeLists.txt)
include(${MAIN_ROOT}/ServerCli/CMakeLists.txt)
