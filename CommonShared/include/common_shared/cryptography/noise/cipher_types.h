// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include "common_shared/cryptography/types/cipher_types.h"

namespace Noise
{
	using namespace Cryptography;

	// we tag the types to make sure we don't mix the functions
	enum class CipherStateInstanceTag
	{
		Handshake,
		Sending,
		Receiving,
	};

	// cipher state exists both during handshake but also during normal message transport phase
	// in case of handshake, each party has one copy of the CipherState
	// during the transport phase each party has two (one for sending, one for receiving)
	template<CipherStateInstanceTag>
	struct CipherState
	{
		CipherKey cipherKey; // k
		Nonce nonce = 0u; // n
	};

	using CipherStateHandshake = CipherState<CipherStateInstanceTag::Handshake>;
	using CipherStateSending = CipherState<CipherStateInstanceTag::Sending>;
	using CipherStateReceiving = CipherState<CipherStateInstanceTag::Receiving>;
} // namespace Noise
