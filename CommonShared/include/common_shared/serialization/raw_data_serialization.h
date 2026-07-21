// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace Serialization
{
	[[nodiscard]] std::optional<std::string> writeShortData(std::span<std::byte> buffer, std::span<const std::byte> data, size_t& outBytesWritten) noexcept;
	[[nodiscard]] std::optional<std::string> readShortDataDynamic(std::span<std::byte> buffer, std::vector<std::byte>& outData, size_t maxDataLength) noexcept;

	[[nodiscard]] std::optional<std::string> writeDataFixedSize(std::span<std::byte> buffer, std::span<const std::byte> data, size_t bufferOffset) noexcept;
	[[nodiscard]] std::optional<std::string> readDataFixedSize(std::span<const std::byte> buffer, std::span<std::byte> outData) noexcept;
} // namespace Serialization
