// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "common_shared/debug/debug_print_helpers.h"

#ifdef DEBUG_CHECKS

#include <cstdio>

namespace Debug::Print
{
	void printSpan(const char* name, std::span<const std::byte> data)
	{
		printf("%s: 0x", name);
		for (size_t j = 0; j < data.size(); j++)
		{
			printf("%02X", static_cast<char>(data[j]));
		}
		printf("\n");
	}
}

#endif // DEBUG_CHECKS
