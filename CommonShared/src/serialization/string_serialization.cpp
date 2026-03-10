// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "common_shared/serialization/string_serialization.h"

#include "common_shared/debug/assert.h"

namespace Serialization
{
	std::optional<std::string> writeShortString(std::span<std::byte> buffer, std::string_view string, size_t& outBytesWritten)
	{
		if (buffer.size() == 0) [[unlikely]]
		{
			reportDebugError("Buffer size was zero, can't write anything");
			return "Buffer size was zero, can't write anything";
		}

		if (string.size() > 255) [[unlikely]]
		{
			reportDebugError("The string is too long to fit its size into one byte. String size: {}", string.size());
			return std::format("The string is too long to fit its size into one byte. String size: {}", string.size());
		}

		if (string.size() >= buffer.size()) [[unlikely]]
		{
			reportDebugError("Tried to fit a string into a buffer of smaller size. String size {}", string.size());
			return std::format("Tried to fit a string into a buffer of smaller size. String size {}", string.size());
		}

		const size_t stringSize = std::min(static_cast<size_t>(255), std::min(buffer.size() - 1, string.size()));

		buffer[0] = static_cast<std::byte>(stringSize);

		std::copy(
			std::bit_cast<std::byte*>(string.data()),
			std::bit_cast<std::byte*>(string.data() + stringSize),
			buffer.data() + 1
		);

		outBytesWritten = stringSize + 1;

		return std::nullopt;
	}

	std::optional<Error> readShortString(std::span<std::byte> stream, std::string& outString, size_t maxStringLength)
	{
		if (stream.size() < 1) [[unlikely]]
		{
			reportDebugError("Trying to read a string but the buffer is too small to fit the size byte");
			return Error{ "Trying to read a string but the buffer is too small to fit the size byte" };
		}

		const size_t stringSize = static_cast<size_t>(stream[0]);

		if (stream.size() < stringSize + 1) [[unlikely]]
		{
			reportDebugError("The string size is greater than the amount of data to read if from, string size: {}, stream size", stringSize, stream.size());
			return Error{ std::format("The string size is greater than the amount of data to read if from, string size: {}, stream size", stringSize, stream.size()) };
		}

		if (stringSize > maxStringLength) [[unlikely]]
		{
			reportDebugError("The received string is longer than max allowed. Received {}, max allowed {}", stringSize, maxStringLength);
			return Error{ std::format("The received string is longer than max allowed. Received {}, max allowed {}", stringSize, maxStringLength) };
		}

		outString.clear();
		outString.reserve(stream.size());
		std::copy(std::bit_cast<char*>(stream.data() + 1), std::bit_cast<char*>(stream.data() + stringSize + 1), std::back_inserter(outString));

		return std::nullopt;
	}
} // namespace Serialization
