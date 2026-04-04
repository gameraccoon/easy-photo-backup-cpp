// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <optional>

#include "common_shared/cryptography/types/cipher_types.h"
#include "common_shared/cryptography/types/dh_types.h"
#include "common_shared/cryptography/types/hash_types.h"

namespace Noise
{
	using namespace Cryptography;

	// cipher state exists both during handshake but also during normal message transport phase
	// in case of handshake, each party has one copy of the CipherState
	// during the transport phase each party has two (one for sending, one for receiving)
	struct CipherState
	{
		CipherKey cipherKey; // k
		Nonce nonce = 0u; // n
	};

	// temporary state that exists only during the handshake phase (on both sides)
	struct SymmetricState
	{
		HashResult handshakeHash; // h
		HashResult chainingKey; // ck

		CipherState cipherState;
	};

	// we tag the types to make sure we don't mix the functions
	enum class HandshakeInstanceTag
	{
		Initiator,
		Responder,
	};

	// temporary state that exists only during the handshake phase (on both sides)
	template<HandshakeInstanceTag>
	struct HandshakeState
	{
		std::optional<Keypair> ephemeralKeys; // e
		std::optional<Keypair> staticKeys; // s
		std::optional<PublicKey> remoteEphemeralKey; // re
		std::optional<PublicKey> remoteStaticKey; // rs

		SymmetricState symmetricState;
	};

	using InitiatorHandshakeState = HandshakeState<HandshakeInstanceTag::Initiator>;
	using ResponderHandshakeState = HandshakeState<HandshakeInstanceTag::Responder>;

	enum class MessageWriteError
	{
		MessageBufferTooSmall,
		EphemeralKeysAlreadySet,
		NoStaticKeys,
		NoEphemeralKeys,
		NoRemoteStaticKey,
		NoRemoteEphemeralKey,
	};

	enum class MessageReadError
	{
		TruncatedMessage,
		RemoteEphemeralKeysAlreadySet,
		NoStaticKeys,
		NoEphemeralKeys,
		NoRemoteStaticKey,
		NoRemoteEphemeralKey,
	};
} // namespace Noise
