// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "common_shared/debug/log.h"

#include <iostream>
#include <mutex>

namespace Debug::Log
{
	namespace Internal
	{
		std::mutex& getDebugLogMutex()
		{
			static std::mutex m;
			return m;
		}
	} // namespace Internal

	void printDebug(const std::string_view text)
	{
		std::lock_guard<std::mutex> lock(Internal::getDebugLogMutex());

		std::cout
			<< text
			<< '\n'
			<< std::flush;
	}
} // namespace Debug::Log
