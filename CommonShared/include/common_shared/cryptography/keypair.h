// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <array>
#include <cstdint>

namespace Cryptography
{
	constexpr std::size_t DHLEN = 32;

	enum class Tag
	{
		PublicKey,
		SecretKey,
		DhResult,
	};

	void secureErase(std::array<uint8_t, DHLEN>& rawData);

	template<Tag>
	struct ByteSequence
	{
		std::array<uint8_t, DHLEN> raw = {};

		ByteSequence() = default;

		// rule of five, we allow copy and move, but require secure erase of each copy
		ByteSequence(ByteSequence&) noexcept = default;
		ByteSequence(ByteSequence&&) noexcept = default;
		ByteSequence& operator=(ByteSequence&) noexcept = default;
		ByteSequence& operator=(ByteSequence&&) noexcept = default;
		~ByteSequence() noexcept { secureErase(raw); }
	};

	using PublicKey = ByteSequence<Tag::PublicKey>;
	using SecretKey = ByteSequence<Tag::SecretKey>;
	using DhResult = ByteSequence<Tag::DhResult>;

	struct Keypair
	{
		PublicKey publicKey;
		SecretKey secretKey;
	};
} // namespace Cryptography
