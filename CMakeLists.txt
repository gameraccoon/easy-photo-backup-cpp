# Copyright (C) Pavel Grebnev 2026
# Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

cmake_minimum_required(VERSION 3.22.1)

set(CMAKE_CXX_STANDARD 20)
set(MAIN_ROOT ${CMAKE_CURRENT_LIST_DIR})

project(EasyPhotoBackup)

include(${MAIN_ROOT}/CommonShared/CMakeLists.txt)
include(${MAIN_ROOT}/ClientShared/CMakeLists.txt)
include(${MAIN_ROOT}/ServerShared/CMakeLists.txt)
include(${MAIN_ROOT}/ClientCli/CMakeLists.txt)
include(${MAIN_ROOT}/ServerCli/CMakeLists.txt)
