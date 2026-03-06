// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "common_shared/nsd/utils_internal.h"

namespace NsdInternalUtils
{
	uint16_t checksum16v1(const std::span<std::byte>& data)
	{
		// this is a very trivial checksum, eventually we want crc16 here
		uint16_t checksum = 0;
		for (uint16_t i = 0; i < data.size(); ++i)
		{
			checksum ^= static_cast<uint16_t>(data[i]) << ((i & 0x1) * 8);
		}
		return checksum;
	}
} // namespace NsdInternalUtils
