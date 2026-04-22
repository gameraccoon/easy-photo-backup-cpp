// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace Serialization
{
	void appendByte(std::vector<std::byte>& inOutStream, std::byte newValue);
	void appendUint8(std::vector<std::byte>& inOutStream, uint8_t newValue);
	void appendUint16(std::vector<std::byte>& inOutStream, uint16_t value);
	void writeUint16(std::byte& outByte1, std::byte& outByte2, uint16_t value);
	uint16_t readUint16(std::byte byte1, std::byte byte2);
	void writeUint64(std::span<std::byte> outSerializedData, uint64_t value);
	uint64_t readUint64(std::span<std::byte> serializedData);
} // namespace Serialization
