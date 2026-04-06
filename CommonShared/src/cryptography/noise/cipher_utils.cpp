// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "common_shared/cryptography/noise/cipher_utils.h"

#include "common_shared/cryptography/primitives/cipher_functions.h"

namespace Noise::Utils
{
	template<CipherStateInstanceTag Tag>
	[[nodiscard]] Cryptography::EncryptResult encryptWithAdGeneric(CipherState<Tag>& cipherState, const std::span<const uint8_t> associatedData, const std::span<const uint8_t> plaintext, const std::span<uint8_t> outCiphertext)
	{
		Cryptography::EncryptResult result = Cryptography::encrypt_chacha20poly1305(cipherState.cipherKey, cipherState.nonce, associatedData, plaintext, outCiphertext);
		if (result == Cryptography::EncryptResult::Success) [[likely]]
		{
			++cipherState.nonce;
		}
		return result;
	}

	template<CipherStateInstanceTag Tag>
	[[nodiscard]] Cryptography::DecryptResult decryptWithAdGeneric(CipherState<Tag>& cipherState, const std::span<const uint8_t> associatedData, const std::span<const uint8_t> ciphertext, const std::span<uint8_t> outPlaintext)
	{
		const Cryptography::DecryptResult result = Cryptography::decrypt_chacha20poly1305(cipherState.cipherKey, cipherState.nonce, associatedData, ciphertext, outPlaintext);
		if (result == Cryptography::DecryptResult::Success) [[likely]]
		{
			++cipherState.nonce;
		}
		return result;
	}

	Cryptography::EncryptResult encryptWithAd(CipherStateSending& cipherState, const std::span<const uint8_t> associatedData, const std::span<const uint8_t> plaintext, const std::span<uint8_t> outCiphertext)
	{
		return encryptWithAdGeneric(cipherState, associatedData, plaintext, outCiphertext);
	}

	Cryptography::DecryptResult decryptWithAd(CipherStateReceiving& cipherState, const std::span<const uint8_t> associatedData, const std::span<const uint8_t> ciphertext, const std::span<uint8_t> outPlaintext)
	{
		return decryptWithAdGeneric(cipherState, associatedData, ciphertext, outPlaintext);
	}

	Cryptography::EncryptResult encryptWithAd(CipherStateHandshake& cipherState, const std::span<const uint8_t> associatedData, const std::span<const uint8_t> plaintext, const std::span<uint8_t> outCiphertext)
	{
		return encryptWithAdGeneric(cipherState, associatedData, plaintext, outCiphertext);
	}

	Cryptography::DecryptResult decryptWithAd(CipherStateHandshake& cipherState, const std::span<const uint8_t> associatedData, const std::span<const uint8_t> ciphertext, const std::span<uint8_t> outPlaintext)
	{
		return decryptWithAdGeneric(cipherState, associatedData, ciphertext, outPlaintext);
	}
} // namespace Noise::Utils
