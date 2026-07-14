// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <span>

#include "common_shared/cryptography/types/hash_types.h"

namespace Cryptography
{
	void hash_blake2b(std::span<const std::byte> data, HashResult& outHash) noexcept;
	void hashWithContext_blake2b(std::span<const std::byte> con, std::span<const std::byte> data, HashResult& outHash) noexcept;
	void HMAC_blake2b(const HashResult& key, std::span<const std::byte> data, HashResult& outMac) noexcept;

	void HKDF_blake2b(
		const HashResult& chainingKey,
		std::span<const std::byte> inputKeyMaterial,
		int numOutputs,
		HashResult& output1,
		HashResult* output2,
		HashResult* output3
	) noexcept;

	// 0 means success
	[[nodiscard]] int hashFile(const std::filesystem::path& path, HashResult& outHash) noexcept;
	[[nodiscard]] int hashFileBytes(std::ifstream& stream, size_t fileSize, HashResult& outHash) noexcept;
} // namespace Cryptography
