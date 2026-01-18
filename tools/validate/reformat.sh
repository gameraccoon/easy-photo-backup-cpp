#!/bin/bash

parent_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )

pushd $parent_path > /dev/null
	python run-clang-format.py ../../CommonShared ../../ClientShared ../../ServerShared ../../ClientCli ../../ServerCli ../../platforms/android/app/src/main/cpp
popd > /dev/null
