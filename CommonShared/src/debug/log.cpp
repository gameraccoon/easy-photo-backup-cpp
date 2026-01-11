// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "common_shared/debug/log.h"

#include <iostream>

namespace debug::log
{
	void printDebug(const std::string_view text)
	{
		std::cout << text;
	}
} // namespace debug::log
