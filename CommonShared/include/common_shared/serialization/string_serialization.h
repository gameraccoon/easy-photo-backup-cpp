// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace Serialization
{
	[[nodiscard]] std::optional<std::string> writeShortString(std::span<std::byte> buffer, std::string_view string, size_t& outBytesWritten) noexcept;
	[[nodiscard]] std::optional<std::string> readShortString(const std::span<const std::byte> buffer, std::string& outString, size_t maxStringLength) noexcept;
} // namespace Serialization
