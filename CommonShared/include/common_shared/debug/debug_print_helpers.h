// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#ifdef DEBUG_CHECKS

#include <span>

#include <zstring_view.hpp>

namespace Debug::Print
{
	void printSpan(std::zstring_view name, std::span<const std::byte> data);
}

#endif // DEBUG_CHECKS
