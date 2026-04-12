// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <filesystem>
#include <optional>

#include "common_shared/bstorage/value.h"

namespace BStorage
{
	[[nodiscard]] std::optional<std::tuple<Value, uint16_t>> loadStorage(const std::filesystem::path& filePath) noexcept;
	[[nodiscard]] bool saveStorage(const std::filesystem::path& filePath, const Value& storage, uint16_t version) noexcept;
}
