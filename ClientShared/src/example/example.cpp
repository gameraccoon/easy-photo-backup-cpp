// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "client_shared/example/example.h"

#include "common_shared/debug/log.h"

namespace example
{
	const int EXAMPLE_CLIENT_VALUE = 100;

	void printAnotherTestValue()
	{
		debug::log::printDebug("client test value");
	}
} // namespace example
