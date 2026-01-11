# Copyright (C) Pavel Grebnev 2026
# Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

cmake_minimum_required(VERSION 3.28)

set (CMAKE_CXX_STANDARD 20)

project(EasyPhotoBackup)

include(CommonShared/CMakeLists.txt)
include(ClientShared/CMakeLists.txt)
include(ServerShared/CMakeLists.txt)
include(ClientCli/CMakeLists.txt)
include(ServerCli/CMakeLists.txt)
