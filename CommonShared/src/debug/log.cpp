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

	void printDebug(const std::string_view text)
	{
		std::lock_guard<std::mutex> lock(Internal::getDebugLogMutex());

#ifdef __ANDROID_API__
		// we can't know if string_view contains null terminator or not, so we have to add it
		// we should add a custom string_view type
		const std::string textStr(text);
		__android_log_print(ANDROID_LOG_DEBUG, "native log", "%s", textStr.c_str());
#else
		std::cout
			<< text
			<< '\n'
			<< std::flush;
#endif
	}
} // namespace Debug::Log
