// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <filesystem>

namespace Files
{
	bool isFilePathAcceptable(const std::filesystem::path& path) noexcept;
} // namespace Files
