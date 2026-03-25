// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "common_shared/cryptography/dh-functions.h"

#include "monocypher.h"

#include "common_shared/cryptography/random.h"

namespace Cryptography
{
	Keypair generateKeypair_x25519()
	{
		Keypair newKeypair;

		fillWithRandomBytes(newKeypair.secretKey.raw);

		static_assert(newKeypair.publicKey.raw.size() == 32, "The crypto_x25519_public_key implementation supports only 32 byte keys");
		static_assert(newKeypair.secretKey.raw.size() == 32, "The crypto_x25519_public_key implementation supports only 32 byte keys");
		crypto_x25519_public_key(newKeypair.publicKey.raw.data(), newKeypair.secretKey.raw.data());

		return newKeypair;
	}

	DhResult diffieHellman_x25519(const SecretKey& secretKey, const PublicKey& publicKey)
	{
		DhResult result;
		// static_assert doesn't work on constexpr functions on arguments for some reason, do sizeof to have at least something
		static_assert(sizeof(publicKey.raw) == 32, "The crypto_x25519 implementation supports only 32 byte keys");
		static_assert(sizeof(secretKey.raw) == 32, "The crypto_x25519 implementation supports only 32 byte keys");
		static_assert(sizeof(publicKey.raw) == 32, "The crypto_x25519 implementation supports only 32 byte keys");
		static_assert(result.raw.size() == 32, "The crypto_x25519 implementation supports only 32 byte keys");
		crypto_x25519(result.raw.data(), secretKey.raw.data(), publicKey.raw.data());
		return result;
	}
} // namespace Cryptography
