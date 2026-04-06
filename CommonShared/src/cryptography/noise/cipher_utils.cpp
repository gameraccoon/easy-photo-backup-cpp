// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "common_shared/cryptography/noise/cipher_utils.h"

#include <limits>

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

	template<CipherStateInstanceTag Tag>
	[[nodiscard]] EncryptResult rekeyGeneric(CipherState<Tag>& cipherState)
	{
		const std::array<uint8_t, Cryptography::CipherKeySize> allZeros = {};
		std::array<uint8_t, Cryptography::CipherKeySize + Cryptography::CipherAuthDataSize> cyphertext;
		constexpr uint64_t nonce = 0xFFFFFFFFFFFFFFFF;
		static_assert(nonce == std::numeric_limits<Nonce>::max(), "Nonce expected to be 64 bit unsigned");
		const EncryptResult result = Cryptography::encrypt_chacha20poly1305(cipherState.cipherKey, nonce, std::span<uint8_t>{}, allZeros, cyphertext);
		if (result == EncryptResult::Success)
		{
			std::copy(cyphertext.begin(), cyphertext.begin() + Cryptography::CipherKeySize, cipherState.cipherKey.raw.begin());
		}
		return result;
	}

	EncryptResult rekey(CipherStateSending& cipherState)
	{
		return rekeyGeneric(cipherState);
	}

	EncryptResult rekey(CipherStateReceiving& cipherState)
	{
		return rekeyGeneric(cipherState);
	}
} // namespace Noise::Utils
