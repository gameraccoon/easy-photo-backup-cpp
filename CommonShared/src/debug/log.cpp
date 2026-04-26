// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "common_shared/debug/log.h"

#include <iostream>
#include <syncstream>

namespace Debug::Log
{
	void printDebug(const std::string_view text)
	{
		std::osyncstream(std::cout)
			<< text
			<< '\n'
			<< std::flush;
	}
} // namespace Debug::Log
