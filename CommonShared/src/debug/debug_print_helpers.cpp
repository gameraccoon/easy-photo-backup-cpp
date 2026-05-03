// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "common_shared/debug/debug_print_helpers.h"

#ifdef DEBUG_CHECKS

#include <format>
#include <iostream>
#include <mutex>

#include "common_shared/debug/log.h"

namespace Debug::Print
{
	void printSpan(const char* name, std::span<const std::byte> data)
	{
		std::lock_guard<std::mutex> lock(Debug::Log::Internal::getDebugLogMutex());

		std::cout << name << ": 0x";
		// incredibly slow but threadsafe
		for (size_t i = 0; i < data.size(); i++)
		{
			std::cout << std::format("{:02x}", static_cast<char>(data[i]));
		}
		std::cout << '\n'
				  << std::flush;
	}
} // namespace Debug::Print

#endif // DEBUG_CHECKS
