// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <span>

namespace Cryptography
{
	void cryptoWipeRawData(std::span<std::byte> rawData) noexcept;
	void cryptoWipeRawMemory(void* memoryStart, size_t memorySizeBytes) noexcept;
}
