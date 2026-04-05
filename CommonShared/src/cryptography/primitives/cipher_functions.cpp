// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "common_shared/cryptography/primitives/cipher_functions.h"

#include <monocypher.h>

#include "common_shared/debug/assert.h"

namespace Cryptography
{
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

	EncryptResult encrypt_chacha20poly1305(
		const CipherKey& key,
		const Nonce nonce,
		const std::span<const uint8_t> associatedData,
		const std::span<const uint8_t> plaintext,
		const std::span<uint8_t> outCiphertext
	) noexcept
	{
		if (plaintext.size() > MaxMessageSize) [[unlikely]]
		{
			reportDebugError("Plaintext for encryption is bigger than max allowed size {} > {}", plaintext.size(), MaxMessageSize);
			return EncryptResult::PlaintextBiggerThanMaxMessageSize;
		}

		if (outCiphertext.size() < plaintext.size() + CipherAuthDataSize) [[unlikely]]
		{
			reportDebugError("Ciphertext buffer is smaller than the plaintext {} < {}", outCiphertext.size() + CipherAuthDataSize, plaintext.size());
			return EncryptResult::CiphertextBufferTooSmall;
		}

		if (outCiphertext.size() > plaintext.size() + CipherAuthDataSize) [[unlikely]]
		{
			reportDebugError("Ciphertext buffer is bigger than the ciphertext, this is likely a logical error {} != {}", outCiphertext.size(), plaintext.size() + CipherAuthDataSize);
			return EncryptResult::CiphertextBufferTooBig;
		}

		const size_t macOffsetInCiphertext = plaintext.size();

		ChaCha20Nonce chaCha20Nonce;
		prepareChaCha20Nonce(nonce, chaCha20Nonce);

		crypto_aead_ctx context;

		static_assert(sizeof(key.raw) == 32);
		static_assert(chaCha20Nonce.raw.size() == 12);
		crypto_aead_init_ietf(&context, key.raw.data(), chaCha20Nonce.raw.data());

		assertFatalRelease(outCiphertext.size() == macOffsetInCiphertext + 16, "The output ciphertext size should exactly fit ciphertext and mac");
		crypto_aead_write(
			&context,
			outCiphertext.data(),
			outCiphertext.data() + macOffsetInCiphertext, // mac goes after text
			associatedData.data(),
			associatedData.size(),
			plaintext.data(),
			plaintext.size()
		);

		crypto_wipe(&context, sizeof(context));

		return EncryptResult::Success;
	}

	DecryptResult decrypt_chacha20poly1305(
		const CipherKey& key,
		const Nonce nonce,
		const std::span<const uint8_t> associatedData,
		const std::span<const uint8_t> ciphertext,
		const std::span<uint8_t> outPlaintext
	) noexcept
	{
		if (ciphertext.size() < CipherAuthDataSize) [[unlikely]]
		{
			reportDebugError("Ciphertext should be at least CipherAuthDataSize of size, but was shorter {}", ciphertext.size());
			return DecryptResult::CiphertextSmallerThanMac;
		}

		if (ciphertext.size() > MaxMessageSize + CipherAuthDataSize) [[unlikely]]
		{
			reportDebugError("Ciphertext is bigger than max allowed size {}", ciphertext.size());
			return DecryptResult::CiphertextBiggerThanMessageLimit;
		}

		if (outPlaintext.size() + CipherAuthDataSize < ciphertext.size()) [[unlikely]]
		{
			reportDebugError("Plaintext buffer is smaller than the plaintext {} < {}", outPlaintext.size(), ciphertext.size() - CipherAuthDataSize);
			return DecryptResult::PlaintextBufferTooSmall;
		}

		if (outPlaintext.size() + CipherAuthDataSize > ciphertext.size()) [[unlikely]]
		{
			reportDebugError("Plaintext buffer is bigger than the plaintext, this is likely a logical error {} != {}", outPlaintext.size(), ciphertext.size() - CipherAuthDataSize);
			return DecryptResult::PlaintextBufferTooBig;
		}

		const size_t macOffsetInCiphertext = ciphertext.size() - CipherAuthDataSize;

		ChaCha20Nonce chaCha20Nonce;
		prepareChaCha20Nonce(nonce, chaCha20Nonce);

		crypto_aead_ctx context;

		static_assert(sizeof(key.raw) == 32);
		static_assert(chaCha20Nonce.raw.size() == 12);
		crypto_aead_init_ietf(&context, key.raw.data(), chaCha20Nonce.raw.data());

		assertFatalRelease(ciphertext.size() == macOffsetInCiphertext + 16, "The output ciphertext size should exactly fit ciphertext and mac");
		int mismatch = crypto_aead_read(
			&context,
			outPlaintext.data(),
			ciphertext.data() + macOffsetInCiphertext, // mac is at the end of ciphertext
			associatedData.data(),
			associatedData.size(),
			ciphertext.data(),
			outPlaintext.size()
		);
		crypto_wipe(&context, sizeof(context));

		if (mismatch != 0) [[unlikely]]
		{
			Debug::Log::printDebug(std::format("Decryption failed, mac mismatch is {}", mismatch));
			return DecryptResult::AuthDataMismatch;
		}

		return DecryptResult::Success;
	}
} // namespace Cryptography
