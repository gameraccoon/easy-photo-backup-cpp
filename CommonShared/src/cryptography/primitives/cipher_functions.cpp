// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "common_shared/cryptography/primitives/cipher_functions.h"

#include <monocypher.h>

#include "common_shared/debug/assert.h"

namespace Cryptography
{
	static constexpr size_t CipherAuthDataSize = 16;
	// we use IETF version of ChaCha20 instead of XChaCha for compatibility with other implementations
	static constexpr size_t ChaCha20NonceSize = 12;
	using ChaCha20Nonce = ByteSequence<Tag::Nonce, ChaCha20NonceSize>;

	static void prepareChaCha20Nonce(const Nonce inNonce, ChaCha20Nonce& outChaCha20Nonce)
	{
		outChaCha20Nonce.raw[0] = 0x0;
		outChaCha20Nonce.raw[1] = 0x0;
		outChaCha20Nonce.raw[2] = 0x0;
		outChaCha20Nonce.raw[3] = 0x0;
		outChaCha20Nonce.raw[4] = static_cast<uint8_t>((inNonce & 0x00000000000000FF) >> 0x00);
		outChaCha20Nonce.raw[5] = static_cast<uint8_t>((inNonce & 0x000000000000FF00) >> 0x08);
		outChaCha20Nonce.raw[6] = static_cast<uint8_t>((inNonce & 0x0000000000FF0000) >> 0x10);
		outChaCha20Nonce.raw[7] = static_cast<uint8_t>((inNonce & 0x00000000FF000000) >> 0x18);
		outChaCha20Nonce.raw[8] = static_cast<uint8_t>((inNonce & 0x000000FF00000000) >> 0x20);
		outChaCha20Nonce.raw[9] = static_cast<uint8_t>((inNonce & 0x0000FF0000000000) >> 0x28);
		outChaCha20Nonce.raw[10] = static_cast<uint8_t>((inNonce & 0x00FF000000000000) >> 0x30);
		outChaCha20Nonce.raw[11] = static_cast<uint8_t>((inNonce & 0xFF00000000000000) >> 0x38);
	}

	void encrypt_chacha20poly1305(
		const CipherKey& key,
		const Nonce nonce,
		const DynByteSequence& associatedData,
		const DynByteSequence& plaintext,
		DynByteSequence& outCiphertext
	) noexcept
	{
		assertFatalRelease(plaintext.size() <= MaxMessageSize, "Plaintext for encryption is longer than available size {}", plaintext.size());
		outCiphertext.clearResize(plaintext.size() + CipherAuthDataSize);
		const size_t macOffsetInCyphertext = plaintext.size();

		ChaCha20Nonce chaCha20Nonce;
		prepareChaCha20Nonce(nonce, chaCha20Nonce);

		crypto_aead_ctx context;

		static_assert(sizeof(key.raw) == 32);
		static_assert(chaCha20Nonce.raw.size() == 12);
		crypto_aead_init_ietf(&context, key.raw.data(), chaCha20Nonce.raw.data());

		assertFatalRelease(outCiphertext.size() == macOffsetInCyphertext + 16, "The output cyphertext sidze should exactly fit cyphertext and mac");
		crypto_aead_write(
			&context,
			outCiphertext.raw.data(),
			outCiphertext.raw.data() + macOffsetInCyphertext, // mac goes after text
			associatedData.raw.data(),
			associatedData.raw.size(),
			plaintext.raw.data(),
			plaintext.raw.size()
		);

		crypto_wipe(&context, sizeof(context));
	}

	int decrypt_chacha20poly1305(
		const CipherKey& key,
		const Nonce nonce,
		const DynByteSequence& associatedData,
		const DynByteSequence& ciphertext,
		DynByteSequence& outPlaintext
	) noexcept
	{
		assertFatalRelease(ciphertext.size() >= CipherAuthDataSize, "Cyphertext should be at least CipherAuthDataSize of size {}", ciphertext.size());
		assertFatalRelease(ciphertext.size() <= MaxMessageSize + CipherAuthDataSize, "Cyphertext is longer than available size {}", ciphertext.size());
		outPlaintext.clearResize(ciphertext.size() - CipherAuthDataSize);
		const size_t macOffsetInCyphertext = ciphertext.size() - CipherAuthDataSize;

		ChaCha20Nonce chaCha20Nonce;
		prepareChaCha20Nonce(nonce, chaCha20Nonce);

		crypto_aead_ctx context;

		static_assert(sizeof(key.raw) == 32);
		static_assert(chaCha20Nonce.raw.size() == 12);
		crypto_aead_init_ietf(&context, key.raw.data(), chaCha20Nonce.raw.data());

		assertFatalRelease(ciphertext.size() == macOffsetInCyphertext + 16, "The output cyphertext sidze should exactly fit cyphertext and mac");
		int mismatch = crypto_aead_read(
			&context,
			outPlaintext.raw.data(),
			ciphertext.raw.data() + macOffsetInCyphertext, // mac is at the end of cyphertext
			associatedData.raw.data(),
			associatedData.raw.size(),
			ciphertext.raw.data(),
			outPlaintext.size()
		);
		crypto_wipe(&context, sizeof(context));
		return mismatch;
	}
} // namespace Cryptography
