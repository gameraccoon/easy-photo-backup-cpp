// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <cstdint>
#include <vector>

namespace Serialization
{
	void appendByte(std::vector<std::byte>& inOutStream, std::byte newValue);
	void appendUint8(std::vector<std::byte>& inOutStream, uint8_t newValue);
	void appendUint16(std::vector<std::byte>& inOutStream, uint16_t value);
	uint16_t readUint16(std::byte byte1, std::byte byte2);
} // namespace Serialization
