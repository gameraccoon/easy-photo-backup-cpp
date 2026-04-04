// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include "common_shared/cryptography/utils/erasable_data.h"

namespace Cryptography
{
	constexpr std::size_t DHLEN = 32;

	using PublicKey = ByteSequence<Tag::PublicKey, DHLEN>;
	using SecretKey = ByteSequence<Tag::SecretKey, DHLEN>;

	using DhResult = ByteSequence<Tag::DhResult, DHLEN>;

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
