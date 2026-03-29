// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include <gtest/gtest.h>

#include "common_shared/cryptography/primitives/dh_functions.h"

TEST(CryptographyDhFunctions, DhX25519_test)
{
	Cryptography::Keypair keys1 = Cryptography::generateKeypair_x25519();
	Cryptography::Keypair keys2 = Cryptography::generateKeypair_x25519();
	Cryptography::DhResult dhResult1 = Cryptography::diffieHellman_x25519(keys1.secretKey, keys2.publicKey);
	Cryptography::DhResult dhResult2 = Cryptography::diffieHellman_x25519(keys2.secretKey, keys1.publicKey);

	EXPECT_EQ(dhResult1.raw, dhResult2.raw);
}
