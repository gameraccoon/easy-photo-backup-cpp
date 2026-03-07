// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "common_shared/serialization/number_serialization.h"

namespace Serialization
{
	void appendByte(std::vector<std::byte>& inOutStream, std::byte newValue)
	{
		inOutStream.push_back(newValue);
	}

	void appendUint8(std::vector<std::byte>& inOutStream, uint8_t newValue)
	{
		inOutStream.push_back(static_cast<std::byte>(newValue));
	}

	void appendUint16(std::vector<std::byte>& inOutStream, uint16_t value)
	{
		if constexpr (std::endian::native == std::endian::little)
		{
			// ReSharper disable once CppDFAUnreachableCode
			inOutStream.push_back(static_cast<std::byte>((value >> 8) & 0xff));
			inOutStream.push_back(static_cast<std::byte>(value & 0xff));
		}
		else
		{
			// ReSharper disable once CppDFAUnreachableCode
			inOutStream.push_back(static_cast<std::byte>(value & 0xff));
			inOutStream.push_back(static_cast<std::byte>((value >> 8) & 0xff));
		}
	}

	void writeUint16(std::byte& outByte1, std::byte& outByte2, uint16_t value)
	{
		if constexpr (std::endian::native == std::endian::little)
		{
			// ReSharper disable once CppDFAUnreachableCode
			outByte1 = static_cast<std::byte>((value >> 8) & 0xff);
			outByte2 = static_cast<std::byte>(value & 0xff);
		}
		else
		{
			// ReSharper disable once CppDFAUnreachableCode
			outByte1 = static_cast<std::byte>(value & 0xff);
			outByte2 = static_cast<std::byte>((value >> 8) & 0xff);
		}
	}

	uint16_t readUint16(std::byte byte1, std::byte byte2)
	{
		if constexpr (std::endian::native == std::endian::little)
		{
			// ReSharper disable once CppDFAUnreachableCode
			return (static_cast<uint16_t>(byte1) << 8) | static_cast<uint16_t>(byte2);
		}
		else
		{
			// ReSharper disable once CppDFAUnreachableCode
			return static_cast<uint16_t>(byte1) | (static_cast<uint16_t>(byte2) << 8);
		}
	}

	int asd2() { return 2; }
} // namespace Serialization
