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

	static void prepareChaCha20Nonce(const Nonce& inNonce, ChaCha20Nonce& outChaCha20Nonce)
	{
		static_assert(sizeof(outChaCha20Nonce.raw) > sizeof(inNonce.raw));
		const size_t realNonceStartOffset = outChaCha20Nonce.size() - inNonce.size();
		// set the nonce at the end and prepend with zeros
		outChaCha20Nonce.raw.fill(0x0);
		std::copy(inNonce.raw.begin(), inNonce.raw.end(), outChaCha20Nonce.raw.begin() + realNonceStartOffset);
	}

	void encrypt_chacha20poly1305(
		const CipherKey& key,
		const Nonce& nonce,
		const DynByteSequence& associatedData,
		const DynByteSequence& plaintext,
		DynByteSequence& outCiphertext
	)
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
		const Nonce& nonce,
		const DynByteSequence& associatedData,
		const DynByteSequence& ciphertext,
		DynByteSequence& outPlaintext
	)
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
