#!/bin/bash

parent_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )

pushd $parent_path > /dev/null
	python run-clang-format.py ../../CommonShared/src ../../CommonShared/include ../../ClientShared/src ../../ClientShared/include ../../ServerShared/src ../../ServerShared/include ../../ClientCli/src ../../ServerCli/src ../../platforms/android/app/src/main/cpp
popd > /dev/null
