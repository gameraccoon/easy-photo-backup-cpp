// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#ifdef DEBUG_CHECKS

#include <span>

namespace Debug::Print
{
	void printSpan(const char* name, std::span<const std::byte> data);
}

#endif // DEBUG_CHECKS
