// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "common_shared/debug/debug_print_helpers.h"

#ifdef DEBUG_CHECKS

#include <format>
#include <iostream>
#include <syncstream>

namespace Debug::Print
{
	void printSpan(const char* name, std::span<const std::byte> data)
	{
		std::osyncstream syncStream(std::cout);
		syncStream << name << ": 0x";
		// incredibly slow but threadsafe
		for (size_t i = 0; i < data.size(); i++)
		{
			syncStream << std::format("{:02x}", static_cast<char>(data[i]));
		}
		syncStream << '\n'
				   << std::flush;
	}
}

#endif // DEBUG_CHECKS
