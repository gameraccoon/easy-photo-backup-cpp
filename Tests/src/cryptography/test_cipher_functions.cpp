// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "tests/helper_utils.h"
#include <gtest/gtest.h>

#include "common_shared/cryptography/cipher-functions.h"
#include "common_shared/cryptography/random.h"

TEST(CryptographyCipherFunctions, chacha20poly1305_roundripTest)
{
	const std::string plaintextStr = "This is the plaintext";

	Cryptography::CipherKey cipherKey;
	vectorToArray(hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), cipherKey.raw);

	Cryptography::Nonce nonce;
	vectorToArray(hexToBytes("AAAAAAAAAAAAAAAA"), nonce.raw);

	const Cryptography::DynByteSequence associatedData = Cryptography::DynByteSequence::fromVector(hexToBytes("BBBBBBBB"));

	const Cryptography::DynByteSequence plaintext = Cryptography::DynByteSequence::fromVector(strToBytes(plaintextStr));

	Cryptography::DynByteSequence ciphertext;
	Cryptography::encrypt_chacha20poly1305(cipherKey, nonce, associatedData, plaintext, ciphertext);

	Cryptography::DynByteSequence resultPlaintext;
	const int res = Cryptography::decrypt_chacha20poly1305(cipherKey, nonce, associatedData, ciphertext, resultPlaintext);
	ASSERT_EQ(res, 0);

	EXPECT_EQ(resultPlaintext.raw, strToBytes(plaintextStr));
}

TEST(CryptographyCipherFunctions, chacha20poly1305_roundripRandomTest)
{
	const std::string plaintextStr = "This is the plaintext";

	Cryptography::CipherKey cipherKey;
	Cryptography::fillWithRandomBytes(cipherKey.raw);

	Cryptography::Nonce nonce;
	Cryptography::fillWithRandomBytes(nonce.raw);

	std::vector<uint8_t> associatedDataRaw;
	associatedDataRaw.resize(20);
	Cryptography::fillWithRandomBytes(associatedDataRaw);
	const Cryptography::DynByteSequence associatedData = Cryptography::DynByteSequence::fromVector(std::move(associatedDataRaw));

	const Cryptography::DynByteSequence plaintext = Cryptography::DynByteSequence::fromVector(strToBytes(plaintextStr));

	Cryptography::DynByteSequence ciphertext;
	Cryptography::encrypt_chacha20poly1305(cipherKey, nonce, associatedData, plaintext, ciphertext);

	Cryptography::DynByteSequence resultPlaintext;
	const int res = Cryptography::decrypt_chacha20poly1305(cipherKey, nonce, associatedData, ciphertext, resultPlaintext);
	ASSERT_EQ(res, 0);

	EXPECT_EQ(resultPlaintext.raw, strToBytes(plaintextStr));
}
