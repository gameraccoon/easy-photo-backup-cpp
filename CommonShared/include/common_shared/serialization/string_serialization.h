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
	struct Error
	{
		std::string errorMessage;
	};

	std::optional<std::string> writeShortString(std::span<std::byte> stream, std::string_view string, size_t& outBytesWritten);
	std::optional<Error> readShortString(std::span<std::byte> stream, std::string& outString, size_t maxStringLength);
} // namespace Serialization
