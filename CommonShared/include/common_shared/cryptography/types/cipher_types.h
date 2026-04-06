// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include "common_shared/cryptography/utils/erasable_data.h"

namespace Cryptography
{
	constexpr size_t CipherKeySize = 32;
	constexpr size_t NonceSize = 8;
	constexpr size_t MaxMessageSize = 65535;
	constexpr size_t CipherAuthDataSize = 16; // mac

	using CipherKey = ByteSequence<Tag::CipherKey, CipherKeySize>;
	using Nonce = uint64_t;

	enum class EncryptResult
	{
		Success,
		// this should be checked in advice, treat as logical error
		PlaintextBiggerThanMaxMessageSize,
		// the buffer is to small to fit the ciphertext, note that ciphertext
		// is bigger than plaintext by the size of MAC
		CiphertextBufferTooSmall,
		// this implementation requires the ciphertext buffer to be exactly of the size
		// of the ciphertext that is going to be placed to it, to make sure that we don't have
		// any off-by-one errors. Seeing this status code signals about a logical error
		CiphertextBufferTooBig,
		// key of all zeros is not allowed and signals about a logical error
		IncorrectEncryptionKey,

		// this error code used down the line, here for concenience
		NoEncryptionKey,
	};

	enum class DecryptResult
	{
		Success,
		// the message is corrupted or tempered with
		AuthDataMismatch,
		// ciphertext is smaller than it can possibly be, possibly truncated message
		CiphertextSmallerThanMac,
		// ciphertext is bigger than the message max size allows, this should be checked
		// in advance and seeing this likely signals about logical error
		CiphertextBiggerThanMessageLimit,
		// plaintext buffer is too small to fit the message, logical error
		PlaintextBufferTooSmall,
		// this implementation requires the plaintext buffer to be exactly of the size
		// of the message that is going to be placed to it, to make sure that we don't have
		// any off-by-one errors. Seeing this status code signals about a logical error
		PlaintextBufferTooBig,
		// key of all zeros is not allowed and signals about a logical error
		IncorrectEncryptionKey,

		// this error code used down the line, here for concenience
		NoEncryptionKey,
	};
} // namespace Cryptography
