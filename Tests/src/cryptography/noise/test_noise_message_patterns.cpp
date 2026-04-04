// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "tests/helper_utils.h"
#include <gtest/gtest.h>

#include "common_shared/cryptography/noise/internal/message_patterns.h"
#include "common_shared/cryptography/noise/internal/utils.h"
#include "common_shared/cryptography/primitives/dh_functions.h"

TEST(CryptographyNoiseMessagePatterns, pattern_e_roundtripFromInitiatorTest)
{
	std::array<std::byte, Cryptography::DHLEN> messageBuffer;

	Noise::InitiatorHandshakeState initiatorHandshakeState;
	{
		size_t writeCursor = 0;
		EXPECT_EQ(Noise::MessagePatterns::writeMessagePattern_e_initiator(initiatorHandshakeState, messageBuffer, writeCursor), std::optional<Noise::MessageWriteError>{});
		EXPECT_EQ(writeCursor, Cryptography::DHLEN);
	}

	Noise::ResponderHandshakeState responderHandshakeState;
	{
		size_t readCursor = 0;
		EXPECT_EQ(Noise::MessagePatterns::readMessagePattern_e_responder(responderHandshakeState, messageBuffer, readCursor), std::optional<Noise::MessageReadError>{});
		EXPECT_EQ(readCursor, Cryptography::DHLEN);
	}

	ASSERT_TRUE(initiatorHandshakeState.ephemeralKeys.has_value());
	ASSERT_TRUE(responderHandshakeState.remoteEphemeralKey.has_value());
	EXPECT_EQ(initiatorHandshakeState.ephemeralKeys->publicKey.raw, responderHandshakeState.remoteEphemeralKey->raw);
	EXPECT_FALSE(isAllZeroes(initiatorHandshakeState.symmetricState.handshakeHash.raw));
	EXPECT_EQ(initiatorHandshakeState.symmetricState.handshakeHash.raw, responderHandshakeState.symmetricState.handshakeHash.raw);

	// check that nothing else was set
	EXPECT_FALSE(initiatorHandshakeState.staticKeys.has_value());
	EXPECT_FALSE(initiatorHandshakeState.remoteEphemeralKey.has_value());
	EXPECT_FALSE(initiatorHandshakeState.remoteStaticKey.has_value());
	EXPECT_EQ(initiatorHandshakeState.symmetricState.cipherState.nonce, static_cast<uint64_t>(0));
	EXPECT_TRUE(isAllZeroes(initiatorHandshakeState.symmetricState.cipherState.cipherKey.raw));
	EXPECT_TRUE(isAllZeroes(initiatorHandshakeState.symmetricState.chainingKey.raw));
	EXPECT_FALSE(responderHandshakeState.ephemeralKeys.has_value());
	EXPECT_FALSE(responderHandshakeState.staticKeys.has_value());
	EXPECT_FALSE(responderHandshakeState.remoteStaticKey.has_value());
	EXPECT_EQ(responderHandshakeState.symmetricState.cipherState.nonce, static_cast<uint64_t>(0));
	EXPECT_TRUE(isAllZeroes(responderHandshakeState.symmetricState.cipherState.cipherKey.raw));
	EXPECT_TRUE(isAllZeroes(responderHandshakeState.symmetricState.chainingKey.raw));
}

TEST(CryptographyNoiseMessagePatterns, pattern_e_roundtripFromResponderTest)
{
	std::array<std::byte, Cryptography::DHLEN> messageBuffer;

	Noise::ResponderHandshakeState responderHandshakeState;
	{
		size_t writeCursor = 0;
		EXPECT_EQ(Noise::MessagePatterns::writeMessagePattern_e_responder(responderHandshakeState, messageBuffer, writeCursor), std::optional<Noise::MessageWriteError>{});
		EXPECT_EQ(writeCursor, Cryptography::DHLEN);
	}

	Noise::InitiatorHandshakeState initiatorHandshakeState;
	{
		size_t readCursor = 0;
		EXPECT_EQ(Noise::MessagePatterns::readMessagePattern_e_initiator(initiatorHandshakeState, messageBuffer, readCursor), std::optional<Noise::MessageReadError>{});
		EXPECT_EQ(readCursor, Cryptography::DHLEN);
	}

	ASSERT_TRUE(responderHandshakeState.ephemeralKeys.has_value());
	ASSERT_TRUE(initiatorHandshakeState.remoteEphemeralKey.has_value());
	EXPECT_EQ(responderHandshakeState.ephemeralKeys->publicKey.raw, initiatorHandshakeState.remoteEphemeralKey->raw);
	EXPECT_FALSE(isAllZeroes(responderHandshakeState.symmetricState.handshakeHash.raw));
	EXPECT_EQ(responderHandshakeState.symmetricState.handshakeHash.raw, initiatorHandshakeState.symmetricState.handshakeHash.raw);

	// check that nothing else was set
	EXPECT_FALSE(responderHandshakeState.staticKeys.has_value());
	EXPECT_FALSE(responderHandshakeState.remoteEphemeralKey.has_value());
	EXPECT_FALSE(responderHandshakeState.remoteStaticKey.has_value());
	EXPECT_EQ(responderHandshakeState.symmetricState.cipherState.nonce, static_cast<uint64_t>(0));
	EXPECT_TRUE(isAllZeroes(responderHandshakeState.symmetricState.cipherState.cipherKey.raw));
	EXPECT_TRUE(isAllZeroes(responderHandshakeState.symmetricState.chainingKey.raw));
	EXPECT_FALSE(initiatorHandshakeState.ephemeralKeys.has_value());
	EXPECT_FALSE(initiatorHandshakeState.staticKeys.has_value());
	EXPECT_FALSE(initiatorHandshakeState.remoteStaticKey.has_value());
	EXPECT_EQ(initiatorHandshakeState.symmetricState.cipherState.nonce, static_cast<uint64_t>(0));
	EXPECT_TRUE(isAllZeroes(initiatorHandshakeState.symmetricState.cipherState.cipherKey.raw));
	EXPECT_TRUE(isAllZeroes(initiatorHandshakeState.symmetricState.chainingKey.raw));
}

TEST(CryptographyNoiseMessagePatterns, pattern_e_writeInitiatorErrorTest)
{
	{
		Noise::InitiatorHandshakeState initiatorHandshakeState;
		std::array<std::byte, Cryptography::DHLEN - 1> messageBuffer;
		size_t writeCursor = 0;
		EXPECT_EQ(Noise::MessagePatterns::writeMessagePattern_e_initiator(initiatorHandshakeState, messageBuffer, writeCursor), std::optional<Noise::MessageWriteError>(Noise::MessageWriteError::MessageBufferTooSmall));
	}

	{
		Noise::InitiatorHandshakeState initiatorHandshakeState;
		initiatorHandshakeState.ephemeralKeys = Cryptography::generateKeypair_x25519();
		std::array<std::byte, Cryptography::DHLEN> messageBuffer;
		size_t writeCursor = 0;
		EXPECT_EQ(Noise::MessagePatterns::writeMessagePattern_e_initiator(initiatorHandshakeState, messageBuffer, writeCursor), std::optional<Noise::MessageWriteError>(Noise::MessageWriteError::EphemeralKeysAlreadySet));
	}
}

TEST(CryptographyNoiseMessagePatterns, pattern_e_writeResponderErrorTest)
{
	{
		Noise::ResponderHandshakeState responderHandshakeState;
		std::array<std::byte, Cryptography::DHLEN - 1> messageBuffer;
		size_t writeCursor = 0;
		EXPECT_EQ(Noise::MessagePatterns::writeMessagePattern_e_responder(responderHandshakeState, messageBuffer, writeCursor), std::optional<Noise::MessageWriteError>(Noise::MessageWriteError::MessageBufferTooSmall));
	}

	{
		Noise::ResponderHandshakeState responderHandshakeState;
		responderHandshakeState.ephemeralKeys = Cryptography::generateKeypair_x25519();
		std::array<std::byte, Cryptography::DHLEN> messageBuffer;
		size_t writeCursor = 0;
		EXPECT_EQ(Noise::MessagePatterns::writeMessagePattern_e_responder(responderHandshakeState, messageBuffer, writeCursor), std::optional<Noise::MessageWriteError>(Noise::MessageWriteError::EphemeralKeysAlreadySet));
	}
}

TEST(CryptographyNoiseMessagePatterns, pattern_e_readInitiatorErrorTest)
{
	{
		Noise::InitiatorHandshakeState initiatorHandshakeState;
		std::array<std::byte, Cryptography::DHLEN - 1> messageBuffer;
		size_t writeCursor = 0;
		EXPECT_EQ(Noise::MessagePatterns::readMessagePattern_e_initiator(initiatorHandshakeState, messageBuffer, writeCursor), std::optional<Noise::MessageReadError>(Noise::MessageReadError::TruncatedMessage));
	}

	{
		Noise::InitiatorHandshakeState initiatorHandshakeState;
		initiatorHandshakeState.remoteEphemeralKey = Cryptography::PublicKey{};
		std::array<std::byte, Cryptography::DHLEN> messageBuffer;
		size_t writeCursor = 0;
		EXPECT_EQ(Noise::MessagePatterns::readMessagePattern_e_initiator(initiatorHandshakeState, messageBuffer, writeCursor), std::optional<Noise::MessageReadError>(Noise::MessageReadError::RemoteEphemeralKeysAlreadySet));
	}
}

TEST(CryptographyNoiseMessagePatterns, pattern_e_readResponderErrorTest)
{
	{
		Noise::ResponderHandshakeState responderHandshakeState;
		std::array<std::byte, Cryptography::DHLEN - 1> messageBuffer;
		size_t writeCursor = 0;
		EXPECT_EQ(Noise::MessagePatterns::readMessagePattern_e_responder(responderHandshakeState, messageBuffer, writeCursor), std::optional<Noise::MessageReadError>(Noise::MessageReadError::TruncatedMessage));
	}

	{
		Noise::ResponderHandshakeState responderHandshakeState;
		responderHandshakeState.remoteEphemeralKey = Cryptography::PublicKey{};
		std::array<std::byte, Cryptography::DHLEN> messageBuffer;
		size_t writeCursor = 0;
		EXPECT_EQ(Noise::MessagePatterns::readMessagePattern_e_responder(responderHandshakeState, messageBuffer, writeCursor), std::optional<Noise::MessageReadError>(Noise::MessageReadError::RemoteEphemeralKeysAlreadySet));
	}
}

TEST(CryptographyNoiseMessagePatterns, pattern_ee_roundtripFromInitiatorTest)
{
	Noise::InitiatorHandshakeState initiatorHandshakeState;
	Noise::ResponderHandshakeState responderHandshakeState;

	// preconditions: ephemeral keys are exchanged
	initiatorHandshakeState.ephemeralKeys = Cryptography::generateKeypair_x25519();
	responderHandshakeState.ephemeralKeys = Cryptography::generateKeypair_x25519();
	initiatorHandshakeState.remoteEphemeralKey = responderHandshakeState.ephemeralKeys->publicKey.clone();
	responderHandshakeState.remoteEphemeralKey = initiatorHandshakeState.ephemeralKeys->publicKey.clone();
	// preconditions: handshake hash is calculated
	Noise::Utils::mixHash(initiatorHandshakeState.ephemeralKeys->publicKey, initiatorHandshakeState.symmetricState);
	Noise::Utils::mixHash(responderHandshakeState.ephemeralKeys->publicKey, initiatorHandshakeState.symmetricState);
	ASSERT_FALSE(isAllZeroes(initiatorHandshakeState.symmetricState.handshakeHash.raw));
	responderHandshakeState.symmetricState.handshakeHash = initiatorHandshakeState.symmetricState.handshakeHash.clone();

	EXPECT_EQ(Noise::MessagePatterns::writeMessagePattern_ee_initiator(initiatorHandshakeState), std::optional<Noise::MessageWriteError>{});
	EXPECT_EQ(Noise::MessagePatterns::readMessagePattern_ee_responder(responderHandshakeState), std::optional<Noise::MessageReadError>{});

	EXPECT_FALSE(isAllZeroes(initiatorHandshakeState.symmetricState.chainingKey.raw));
	EXPECT_FALSE(isAllZeroes(responderHandshakeState.symmetricState.chainingKey.raw));
	EXPECT_EQ(initiatorHandshakeState.symmetricState.chainingKey.raw, responderHandshakeState.symmetricState.chainingKey.raw);
	EXPECT_FALSE(isAllZeroes(initiatorHandshakeState.symmetricState.cipherState.cipherKey.raw));
	EXPECT_FALSE(isAllZeroes(responderHandshakeState.symmetricState.cipherState.cipherKey.raw));
	EXPECT_EQ(initiatorHandshakeState.symmetricState.cipherState.cipherKey.raw, responderHandshakeState.symmetricState.cipherState.cipherKey.raw);
	EXPECT_EQ(initiatorHandshakeState.symmetricState.cipherState.nonce, static_cast<uint64_t>(0));
	EXPECT_EQ(responderHandshakeState.symmetricState.cipherState.nonce, static_cast<uint64_t>(0));
}

TEST(CryptographyNoiseMessagePatterns, pattern_ee_roundtripFromResponderTest)
{
	Noise::InitiatorHandshakeState initiatorHandshakeState;
	Noise::ResponderHandshakeState responderHandshakeState;

	// preconditions: both sides have ephemeral keys and know the other's public ephemeral
	initiatorHandshakeState.ephemeralKeys = Cryptography::generateKeypair_x25519();
	responderHandshakeState.ephemeralKeys = Cryptography::generateKeypair_x25519();
	initiatorHandshakeState.remoteEphemeralKey = responderHandshakeState.ephemeralKeys->publicKey.clone();
	responderHandshakeState.remoteEphemeralKey = initiatorHandshakeState.ephemeralKeys->publicKey.clone();
	// preconditions: handshake hash is calculated
	Noise::Utils::mixHash(initiatorHandshakeState.ephemeralKeys->publicKey, responderHandshakeState.symmetricState);
	Noise::Utils::mixHash(responderHandshakeState.ephemeralKeys->publicKey, responderHandshakeState.symmetricState);
	ASSERT_FALSE(isAllZeroes(responderHandshakeState.symmetricState.handshakeHash.raw));
	initiatorHandshakeState.symmetricState.handshakeHash = responderHandshakeState.symmetricState.handshakeHash.clone();

	EXPECT_EQ(Noise::MessagePatterns::writeMessagePattern_ee_responder(responderHandshakeState), std::optional<Noise::MessageWriteError>{});
	EXPECT_EQ(Noise::MessagePatterns::readMessagePattern_ee_initiator(initiatorHandshakeState), std::optional<Noise::MessageReadError>{});

	EXPECT_FALSE(isAllZeroes(responderHandshakeState.symmetricState.chainingKey.raw));
	EXPECT_FALSE(isAllZeroes(initiatorHandshakeState.symmetricState.chainingKey.raw));
	EXPECT_EQ(responderHandshakeState.symmetricState.chainingKey.raw, initiatorHandshakeState.symmetricState.chainingKey.raw);
	EXPECT_FALSE(isAllZeroes(responderHandshakeState.symmetricState.cipherState.cipherKey.raw));
	EXPECT_FALSE(isAllZeroes(initiatorHandshakeState.symmetricState.cipherState.cipherKey.raw));
	EXPECT_EQ(responderHandshakeState.symmetricState.cipherState.cipherKey.raw, initiatorHandshakeState.symmetricState.cipherState.cipherKey.raw);
	EXPECT_EQ(responderHandshakeState.symmetricState.cipherState.nonce, static_cast<uint64_t>(0));
	EXPECT_EQ(initiatorHandshakeState.symmetricState.cipherState.nonce, static_cast<uint64_t>(0));
}

TEST(CryptographyNoiseMessagePatterns, pattern_ee_writeInitiatorErrorTest)
{
	{
		Noise::InitiatorHandshakeState initiatorHandshakeState;
		initiatorHandshakeState.remoteEphemeralKey = Cryptography::PublicKey{};
		EXPECT_EQ(Noise::MessagePatterns::writeMessagePattern_ee_initiator(initiatorHandshakeState), std::optional<Noise::MessageWriteError>(Noise::MessageWriteError::NoEphemeralKeys));
	}

	{
		Noise::InitiatorHandshakeState initiatorHandshakeState;
		initiatorHandshakeState.ephemeralKeys = Cryptography::generateKeypair_x25519();
		EXPECT_EQ(Noise::MessagePatterns::writeMessagePattern_ee_initiator(initiatorHandshakeState), std::optional<Noise::MessageWriteError>(Noise::MessageWriteError::NoRemoteEphemeralKey));
	}
}

TEST(CryptographyNoiseMessagePatterns, pattern_ee_readResponderErrorTest)
{
	{
		Noise::ResponderHandshakeState responderHandshakeState;
		responderHandshakeState.remoteEphemeralKey = Cryptography::PublicKey{};
		EXPECT_EQ(Noise::MessagePatterns::readMessagePattern_ee_responder(responderHandshakeState), std::optional<Noise::MessageReadError>(Noise::MessageReadError::NoEphemeralKeys));
	}

	{
		Noise::ResponderHandshakeState responderHandshakeState;
		responderHandshakeState.ephemeralKeys = Cryptography::generateKeypair_x25519();
		EXPECT_EQ(Noise::MessagePatterns::readMessagePattern_ee_responder(responderHandshakeState), std::optional<Noise::MessageReadError>(Noise::MessageReadError::NoRemoteEphemeralKey));
	}
}

TEST(CryptographyNoiseMessagePatterns, pattern_ee_writeResponderErrorTest)
{
	{
		Noise::ResponderHandshakeState responderHandshakeState;
		responderHandshakeState.remoteEphemeralKey = Cryptography::PublicKey{};
		EXPECT_EQ(Noise::MessagePatterns::writeMessagePattern_ee_responder(responderHandshakeState), std::optional<Noise::MessageWriteError>(Noise::MessageWriteError::NoEphemeralKeys));
	}

	{
		Noise::ResponderHandshakeState responderHandshakeState;
		responderHandshakeState.ephemeralKeys = Cryptography::generateKeypair_x25519();
		EXPECT_EQ(Noise::MessagePatterns::writeMessagePattern_ee_responder(responderHandshakeState), std::optional<Noise::MessageWriteError>(Noise::MessageWriteError::NoRemoteEphemeralKey));
	}
}

TEST(CryptographyNoiseMessagePatterns, pattern_ee_readInitiatorErrorTest)
{
	{
		Noise::InitiatorHandshakeState initiatorHandshakeState;
		initiatorHandshakeState.remoteEphemeralKey = Cryptography::PublicKey{};
		EXPECT_EQ(Noise::MessagePatterns::readMessagePattern_ee_initiator(initiatorHandshakeState), std::optional<Noise::MessageReadError>(Noise::MessageReadError::NoEphemeralKeys));
	}

	{
		Noise::InitiatorHandshakeState initiatorHandshakeState;
		initiatorHandshakeState.ephemeralKeys = Cryptography::generateKeypair_x25519();
		EXPECT_EQ(Noise::MessagePatterns::readMessagePattern_ee_initiator(initiatorHandshakeState), std::optional<Noise::MessageReadError>(Noise::MessageReadError::NoRemoteEphemeralKey));
	}
}

TEST(CryptographyNoiseMessagePatterns, pattern_es_roundtripFromInitiatorTest)
{
	Noise::InitiatorHandshakeState initiatorHandshakeState;
	Noise::ResponderHandshakeState responderHandshakeState;

	// preconditions: static keys are exchanged
	initiatorHandshakeState.staticKeys = Cryptography::generateKeypair_x25519();
	responderHandshakeState.staticKeys = Cryptography::generateKeypair_x25519();
	initiatorHandshakeState.remoteStaticKey = responderHandshakeState.staticKeys->publicKey.clone();
	responderHandshakeState.remoteStaticKey = initiatorHandshakeState.staticKeys->publicKey.clone();
	// preconditions: ephemeral key is sent from initiator
	initiatorHandshakeState.ephemeralKeys = Cryptography::generateKeypair_x25519();
	responderHandshakeState.remoteEphemeralKey = initiatorHandshakeState.ephemeralKeys->publicKey.clone();
	// preconditions: handshake hash is calculated
	Noise::Utils::mixHash(initiatorHandshakeState.ephemeralKeys->publicKey, initiatorHandshakeState.symmetricState);
	ASSERT_FALSE(isAllZeroes(initiatorHandshakeState.symmetricState.handshakeHash.raw));
	responderHandshakeState.symmetricState.handshakeHash = initiatorHandshakeState.symmetricState.handshakeHash.clone();

	EXPECT_EQ(Noise::MessagePatterns::writeMessagePattern_es_initiator(initiatorHandshakeState), std::optional<Noise::MessageWriteError>{});
	EXPECT_EQ(Noise::MessagePatterns::readMessagePattern_es_responder(responderHandshakeState), std::optional<Noise::MessageReadError>{});

	EXPECT_FALSE(isAllZeroes(initiatorHandshakeState.symmetricState.chainingKey.raw));
	EXPECT_EQ(initiatorHandshakeState.symmetricState.chainingKey.raw, responderHandshakeState.symmetricState.chainingKey.raw);
	EXPECT_EQ(initiatorHandshakeState.symmetricState.cipherState.nonce, static_cast<uint64_t>(0));
	EXPECT_EQ(responderHandshakeState.symmetricState.cipherState.nonce, static_cast<uint64_t>(0));
	EXPECT_FALSE(isAllZeroes(initiatorHandshakeState.symmetricState.cipherState.cipherKey.raw));
	EXPECT_EQ(initiatorHandshakeState.symmetricState.cipherState.cipherKey.raw, responderHandshakeState.symmetricState.cipherState.cipherKey.raw);
}

TEST(CryptographyNoiseMessagePatterns, pattern_es_writeInitiatorErrorTest)
{
	{
		Noise::InitiatorHandshakeState initiatorHandshakeState;
		initiatorHandshakeState.remoteStaticKey = Cryptography::PublicKey{};
		EXPECT_EQ(Noise::MessagePatterns::writeMessagePattern_es_initiator(initiatorHandshakeState), std::optional<Noise::MessageWriteError>(Noise::MessageWriteError::NoEphemeralKeys));
	}

	{
		Noise::InitiatorHandshakeState initiatorHandshakeState;
		initiatorHandshakeState.ephemeralKeys = Cryptography::generateKeypair_x25519();
		EXPECT_EQ(Noise::MessagePatterns::writeMessagePattern_es_initiator(initiatorHandshakeState), std::optional<Noise::MessageWriteError>(Noise::MessageWriteError::NoRemoteStaticKey));
	}
}

TEST(CryptographyNoiseMessagePatterns, pattern_es_readResponderErrorTest)
{
	{
		Noise::ResponderHandshakeState responderHandshakeState;
		responderHandshakeState.remoteEphemeralKey = Cryptography::PublicKey{};
		EXPECT_EQ(Noise::MessagePatterns::readMessagePattern_es_responder(responderHandshakeState), std::optional<Noise::MessageReadError>(Noise::MessageReadError::NoStaticKeys));
	}

	{
		Noise::ResponderHandshakeState responderHandshakeState;
		responderHandshakeState.staticKeys = Cryptography::generateKeypair_x25519();
		EXPECT_EQ(Noise::MessagePatterns::readMessagePattern_es_responder(responderHandshakeState), std::optional<Noise::MessageReadError>(Noise::MessageReadError::NoRemoteEphemeralKey));
	}
}

TEST(CryptographyNoiseMessagePatterns, pattern_se_roundtripTest)
{
	Noise::ResponderHandshakeState responderHandshakeState;
	Noise::InitiatorHandshakeState initiatorHandshakeState;

	// preconditions: static keys are exchanged
	initiatorHandshakeState.staticKeys = Cryptography::generateKeypair_x25519();
	responderHandshakeState.staticKeys = Cryptography::generateKeypair_x25519();
	initiatorHandshakeState.remoteStaticKey = responderHandshakeState.staticKeys->publicKey.clone();
	responderHandshakeState.remoteStaticKey = initiatorHandshakeState.staticKeys->publicKey.clone();
	// preconditions: ephemeral key is sent from responder
	responderHandshakeState.ephemeralKeys = Cryptography::generateKeypair_x25519();
	initiatorHandshakeState.remoteEphemeralKey = responderHandshakeState.ephemeralKeys->publicKey.clone();
	// preconditions: handshake hash is calculated
	Noise::Utils::mixHash(initiatorHandshakeState.ephemeralKeys->publicKey, initiatorHandshakeState.symmetricState);
	ASSERT_FALSE(isAllZeroes(initiatorHandshakeState.symmetricState.handshakeHash.raw));
	responderHandshakeState.symmetricState.handshakeHash = initiatorHandshakeState.symmetricState.handshakeHash.clone();

	EXPECT_EQ(Noise::MessagePatterns::writeMessagePattern_se_responder(responderHandshakeState), std::optional<Noise::MessageWriteError>{});
	EXPECT_EQ(Noise::MessagePatterns::readMessagePattern_se_initiator(initiatorHandshakeState), std::optional<Noise::MessageReadError>{});

	EXPECT_FALSE(isAllZeroes(responderHandshakeState.symmetricState.chainingKey.raw));
	EXPECT_EQ(responderHandshakeState.symmetricState.chainingKey.raw, initiatorHandshakeState.symmetricState.chainingKey.raw);
	EXPECT_FALSE(isAllZeroes(responderHandshakeState.symmetricState.cipherState.cipherKey.raw));
	EXPECT_EQ(responderHandshakeState.symmetricState.cipherState.cipherKey.raw, initiatorHandshakeState.symmetricState.cipherState.cipherKey.raw);
	EXPECT_EQ(responderHandshakeState.symmetricState.cipherState.nonce, static_cast<uint64_t>(0));
	EXPECT_EQ(initiatorHandshakeState.symmetricState.cipherState.nonce, static_cast<uint64_t>(0));
}

TEST(CryptographyNoiseMessagePatterns, pattern_se_writeResponderErrorTest)
{
	{
		Noise::ResponderHandshakeState responderHandshakeState;
		responderHandshakeState.remoteStaticKey = Cryptography::PublicKey{};
		EXPECT_EQ(Noise::MessagePatterns::writeMessagePattern_se_responder(responderHandshakeState), std::optional<Noise::MessageWriteError>(Noise::MessageWriteError::NoEphemeralKeys));
	}

	{
		Noise::ResponderHandshakeState responderHandshakeState;
		responderHandshakeState.ephemeralKeys = Cryptography::generateKeypair_x25519();
		EXPECT_EQ(Noise::MessagePatterns::writeMessagePattern_se_responder(responderHandshakeState), std::optional<Noise::MessageWriteError>(Noise::MessageWriteError::NoRemoteStaticKey));
	}
}

TEST(CryptographyNoiseMessagePatterns, pattern_se_readInitiatorErrorTest)
{
	{
		Noise::InitiatorHandshakeState initiatorHandshakeState;
		initiatorHandshakeState.remoteEphemeralKey = Cryptography::PublicKey{};
		EXPECT_EQ(Noise::MessagePatterns::readMessagePattern_se_initiator(initiatorHandshakeState), std::optional<Noise::MessageReadError>(Noise::MessageReadError::NoStaticKeys));
	}

	{
		Noise::InitiatorHandshakeState initiatorHandshakeState;
		initiatorHandshakeState.staticKeys = Cryptography::generateKeypair_x25519();
		EXPECT_EQ(Noise::MessagePatterns::readMessagePattern_se_initiator(initiatorHandshakeState), std::optional<Noise::MessageReadError>(Noise::MessageReadError::NoRemoteEphemeralKey));
	}
}

TEST(CryptographyNoiseMessagePatterns, pattern_ss_roundtripTest)
{
	Noise::InitiatorHandshakeState initiatorHandshakeState;
	Noise::ResponderHandshakeState responderHandshakeState;

	// preconditions: static keys are exchanged
	initiatorHandshakeState.staticKeys = Cryptography::generateKeypair_x25519();
	responderHandshakeState.staticKeys = Cryptography::generateKeypair_x25519();
	initiatorHandshakeState.remoteStaticKey = responderHandshakeState.staticKeys->publicKey.clone();
	responderHandshakeState.remoteStaticKey = initiatorHandshakeState.staticKeys->publicKey.clone();
	// preconditions: handshake hash is calculated
	Noise::Utils::mixHash(initiatorHandshakeState.staticKeys->publicKey, initiatorHandshakeState.symmetricState);
	ASSERT_FALSE(isAllZeroes(initiatorHandshakeState.symmetricState.handshakeHash.raw));
	responderHandshakeState.symmetricState.handshakeHash = initiatorHandshakeState.symmetricState.handshakeHash.clone();

	EXPECT_EQ(Noise::MessagePatterns::writeMessagePattern_ss_initiator(initiatorHandshakeState), std::optional<Noise::MessageWriteError>{});
	EXPECT_EQ(Noise::MessagePatterns::readMessagePattern_ss_responder(responderHandshakeState), std::optional<Noise::MessageReadError>{});

	EXPECT_FALSE(isAllZeroes(initiatorHandshakeState.symmetricState.chainingKey.raw));
	EXPECT_FALSE(isAllZeroes(responderHandshakeState.symmetricState.chainingKey.raw));
	EXPECT_EQ(initiatorHandshakeState.symmetricState.chainingKey.raw, responderHandshakeState.symmetricState.chainingKey.raw);
	EXPECT_FALSE(isAllZeroes(initiatorHandshakeState.symmetricState.cipherState.cipherKey.raw));
	EXPECT_FALSE(isAllZeroes(responderHandshakeState.symmetricState.cipherState.cipherKey.raw));
	EXPECT_EQ(initiatorHandshakeState.symmetricState.cipherState.cipherKey.raw, responderHandshakeState.symmetricState.cipherState.cipherKey.raw);
	EXPECT_EQ(initiatorHandshakeState.symmetricState.cipherState.nonce, static_cast<uint64_t>(0));
	EXPECT_EQ(responderHandshakeState.symmetricState.cipherState.nonce, static_cast<uint64_t>(0));
}

TEST(CryptographyNoiseMessagePatterns, pattern_ss_writeInitiatorErrorTest)
{
	{
		Noise::InitiatorHandshakeState initiatorHandshakeState;
		initiatorHandshakeState.remoteStaticKey = Cryptography::PublicKey{};
		EXPECT_EQ(Noise::MessagePatterns::writeMessagePattern_ss_initiator(initiatorHandshakeState), std::optional<Noise::MessageWriteError>(Noise::MessageWriteError::NoStaticKeys));
	}

	{
		Noise::InitiatorHandshakeState initiatorHandshakeState;
		initiatorHandshakeState.staticKeys = Cryptography::generateKeypair_x25519();
		EXPECT_EQ(Noise::MessagePatterns::writeMessagePattern_ss_initiator(initiatorHandshakeState), std::optional<Noise::MessageWriteError>(Noise::MessageWriteError::NoRemoteStaticKey));
	}
}

TEST(CryptographyNoiseMessagePatterns, pattern_ss_readResponderErrorTest)
{
	{
		Noise::ResponderHandshakeState responderHandshakeState;
		responderHandshakeState.remoteStaticKey = Cryptography::PublicKey{};
		EXPECT_EQ(Noise::MessagePatterns::readMessagePattern_ss_responder(responderHandshakeState), std::optional<Noise::MessageReadError>(Noise::MessageReadError::NoStaticKeys));
	}

	{
		Noise::ResponderHandshakeState responderHandshakeState;
		responderHandshakeState.staticKeys = Cryptography::generateKeypair_x25519();
		EXPECT_EQ(Noise::MessagePatterns::readMessagePattern_ss_responder(responderHandshakeState), std::optional<Noise::MessageReadError>(Noise::MessageReadError::NoRemoteStaticKey));
	}
}
