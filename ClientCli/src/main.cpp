// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include <format>

#include "common_shared/debug/log.h"

#include "client_shared/example/example.h"

int main()
{
	debug::log::printDebug(std::format("Hello, World! {}\n", example::EXAMPLE_CLIENT_VALUE));
	example::printAnotherTestValue();
	return 0;
}
