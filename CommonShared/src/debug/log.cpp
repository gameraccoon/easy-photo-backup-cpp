// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "common_shared/debug/log.h"

#include <mutex>

#ifdef __ANDROID_API__
#include <android/log.h>
#else
#include <iostream>
#endif

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

	void printDebug(const std::zstring_view text)
	{
		std::lock_guard<std::mutex> lock(Internal::getDebugLogMutex());

#ifdef __ANDROID_API__
		__android_log_print(ANDROID_LOG_DEBUG, "native log", "%s", text.c_str());
#else
		std::cout
			<< text
			<< '\n'
			<< std::flush;
#endif
	}
} // namespace Debug::Log
