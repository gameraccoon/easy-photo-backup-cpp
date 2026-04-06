// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <optional>

#include "common_shared/cryptography/noise/cipher_types.h"
#include "common_shared/cryptography/types/dh_types.h"
#include "common_shared/cryptography/types/hash_types.h"

namespace Noise
{
	using namespace Cryptography;

	using CipherStateHandshake = CipherState<CipherStateInstanceTag::Handshake>;
	using CipherStateSending = CipherState<CipherStateInstanceTag::Sending>;
	using CipherStateReceiving = CipherState<CipherStateInstanceTag::Receiving>;

	// temporary state that exists only during the handshake phase (on both sides)
	struct SymmetricState
	{
		HashResult handshakeHash; // h
		HashResult chainingKey; // ck

		// instead of making k optional, we make the whole state optional
		std::optional<CipherStateHandshake> cipherState;
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
		EncryptionFailed,
		InvalidPublicKey,
	};

	enum class MessageReadError
	{
		TruncatedMessage,
		RemoteEphemeralKeyAlreadySet,
		RemoteStaticKeyAlreadySet,
		NoStaticKeys,
		NoEphemeralKeys,
		NoRemoteStaticKey,
		NoRemoteEphemeralKey,
		DecryptionFailed,
		InvalidPublicKey,
	};
} // namespace Noise
