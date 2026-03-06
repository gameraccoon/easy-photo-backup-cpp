#!/bin/bash

return_code=0

function check {
	"$@"
	local exit_code=$?
	if [ $exit_code -ne 0 ]; then
		return_code=1
	fi
}

check cppcheck -q --error-exitcode=1 --check-level=exhaustive ClientCli --file-filter=ClientCli/src/**
check cppcheck -q --error-exitcode=1 --check-level=exhaustive ClientShared --file-filter=ClientShared/src/**
check cppcheck -q --error-exitcode=1 --check-level=exhaustive CommonShared --file-filter=CommonShared/src/**
check cppcheck -q --error-exitcode=1 --check-level=exhaustive ServerCli --file-filter=ServerCli/src/**
check cppcheck -q --error-exitcode=1 --check-level=exhaustive ServerShared --file-filter=ServerShared/src/**
check cppcheck -q --error-exitcode=1 --check-level=exhaustive platforms/android/app/src/main/cpp

exit $return_code
