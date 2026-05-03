// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <format>
#include <string_view>

namespace Debug::Log
{
	void printDebug(std::string_view text);

	template<typename... Args>
	void printDebug(const std::format_string<Args...>& message, Args... args)
	{
		printDebug(std::format(message, std::forward<Args>(args)...));
	}
} // namespace Debug::Log
