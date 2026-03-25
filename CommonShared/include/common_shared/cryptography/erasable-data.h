// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <array>
#include <cstdint>
#include <span>

namespace Cryptography
{
	// we plan to use this data for very speicific needs, and don't want to mix those needs
	enum class Tag
	{
		PublicKey,
		SecretKey,
		DhResult,
		HashResult,
		TempInternalBuffer,
	};

	void secureErase(std::span<uint8_t> rawData);

	template<Tag, std::size_t DataLen>
	struct ByteSequence
	{
		std::array<uint8_t, DataLen> raw = {};

		ByteSequence() = default;

		ByteSequence clone() { return ByteSequence{ .raw = raw }; }

		// rule of five, no implicit copy, allow move, require secure erase of each copy
		ByteSequence(ByteSequence&) noexcept = delete;
		ByteSequence(ByteSequence&&) noexcept = default;
		ByteSequence& operator=(ByteSequence&) noexcept = delete;
		ByteSequence& operator=(ByteSequence&&) noexcept = default;
		~ByteSequence() noexcept { secureErase(raw); }
	};
} // namespace Cryptography
