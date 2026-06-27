// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "common_shared/hash_utils.h"

namespace Hash
{
	size_t hashSpan(std::span<const std::byte> span) noexcept
	{
		// based on https://stackoverflow.com/a/12996028/3787296
		// this can probably replaced with something faster
		std::size_t seed = span.size();
		for (const std::byte b : span)
		{
			size_t x = static_cast<size_t>(b);
			x = ((x >> 16) ^ x) * 0x45d9f3b;
			x = ((x >> 16) ^ x) * 0x45d9f3b;
			x = (x >> 16) ^ x;
			seed ^= x + 0x9e3779b9 + (seed << 6) + (seed >> 2);
		}
		return seed;
	}
} // namespace Hash
