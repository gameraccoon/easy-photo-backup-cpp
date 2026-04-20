// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include "common_shared/cryptography/utils/erasable_data.h"

namespace Cryptography
{
	constexpr std::size_t DHLEN = 32;

	using PublicKey = ByteSequence<ByteSequenceTag::PublicKey, DHLEN>;
	using SecretKey = ByteSequence<ByteSequenceTag::SecretKey, DHLEN>;

	using DhResult = ByteSequence<ByteSequenceTag::DhResult, DHLEN>;

	struct Keypair
	{
		PublicKey publicKey;
		SecretKey secretKey;

		[[nodiscard]] Keypair clone() const noexcept
		{
			return Keypair{
				.publicKey = publicKey.clone(),
				.secretKey = secretKey.clone(),
			};
		}
	};
} // namespace Cryptography
