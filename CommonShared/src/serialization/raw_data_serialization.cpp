// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "common_shared/serialization/raw_data_serialization.h"

#include "common_shared/debug/assert.h"

namespace Serialization
{
	std::optional<std::string> writeShortData(std::span<std::byte> buffer, std::span<std::byte> data, size_t& outBytesWritten)
	{
		if (buffer.size() == 0) [[unlikely]]
		{
			reportDebugError("Buffer size was zero, can't write anything");
			return "Buffer size was zero, can't write anything";
		}

		if (data.size() > 255) [[unlikely]]
		{
			reportDebugError("The data is too big to fit its size into one byte. Data size: {}", data.size());
			return std::format("The data is too big to fit its size into one byte. Data size: {}", data.size());
		}

		if (data.size() >= buffer.size()) [[unlikely]]
		{
			reportDebugError("Tried to fit the data into a buffer of smaller size. Data size {}", data.size());
			return std::format("Tried to fit the data into a buffer of smaller size. Data size {}", data.size());
		}

		const size_t dataSize = std::min(static_cast<size_t>(255), std::min(buffer.size() - 1, data.size()));

		buffer[0] = static_cast<std::byte>(dataSize);

		std::copy(
			data.data(),
			data.data() + dataSize,
			buffer.data() + 1
		);

		outBytesWritten = dataSize + 1;

		return std::nullopt;
	}

	std::optional<std::string> readShortDataDynamic(std::span<std::byte> buffer, std::vector<std::byte>& outData, size_t maxDataLength)
	{
		if (buffer.size() < 1) [[unlikely]]
		{
			reportDebugError("Trying to read a data but the buffer is too small to fit the size byte");
			return "Trying to read a data but the buffer is too small to fit the size byte";
		}

		const size_t dataSize = static_cast<size_t>(buffer[0]);

		if (buffer.size() < dataSize + 1) [[unlikely]]
		{
			reportDebugError("The data size is greater than the amount of data to read if from, data size: {}, stream size", dataSize, buffer.size());
			return std::format("The data size is greater than the amount of data to read if from, data size: {}, stream size", dataSize, buffer.size());
		}

		if (dataSize > maxDataLength) [[unlikely]]
		{
			reportDebugError("The received data is longer than max allowed. Received {}, max allowed {}", dataSize, maxDataLength);
			return std::format("The received data is longer than max allowed. Received {}, max allowed {}", dataSize, maxDataLength);
		}

		outData.clear();
		outData.reserve(buffer.size());
		std::copy(buffer.data() + 1, buffer.data() + dataSize + 1, std::back_inserter(outData));

		return std::nullopt;
	}
} // namespace Serialization
