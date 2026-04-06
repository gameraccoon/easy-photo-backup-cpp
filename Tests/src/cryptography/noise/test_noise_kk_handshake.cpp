// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include <gtest/gtest.h>

#include "common_shared/cryptography/noise/noise_kk_handshake.h"
#include "common_shared/cryptography/primitives/dh_functions.h"

TEST(CryptographyNoiseKKHandshake, roundtripTest)
{
	using namespace Noise::NoiseKK;

	// pre-shared keys
	Keypair initiatorStaticKeys = generateKeypair_x25519();
	Keypair responderStaticKeys = generateKeypair_x25519();

	// initialize both parts
	Noise::InitiatorHandshakeState initiatorHandshakeState = initializeInitiator(initiatorStaticKeys, responderStaticKeys.publicKey);
	Noise::ResponderHandshakeState responderHandshakeState = initializeResponder(responderStaticKeys, initiatorStaticKeys.publicKey);

	std::array<std::byte, DHLEN> messageBuffer;
	size_t initiatorCursor = 0;
	EXPECT_EQ(appendHandshakeMessage1(initiatorHandshakeState, messageBuffer, initiatorCursor), std::nullopt);

	size_t receiverCursor = 0;
	EXPECT_EQ(processHandshakeMessage1(responderHandshakeState, messageBuffer, receiverCursor), std::nullopt);

	receiverCursor = 0;
	const auto result1 = appendHandshakeMessage2(std::move(responderHandshakeState), messageBuffer, receiverCursor);

	initiatorCursor = 0;
	const auto result2 = processHandshakeMessage2(std::move(initiatorHandshakeState), messageBuffer, initiatorCursor);

	ASSERT_TRUE(std::holds_alternative<HandshakeResult>(result1));
	ASSERT_TRUE(std::holds_alternative<HandshakeResult>(result2));

	EXPECT_EQ(std::get<HandshakeResult>(result1).receivingCipherState.cipherKey.raw, std::get<HandshakeResult>(result2).sendingCipherState.cipherKey.raw);
	EXPECT_EQ(std::get<HandshakeResult>(result1).receivingCipherState.nonce, std::get<HandshakeResult>(result2).sendingCipherState.nonce);

	EXPECT_EQ(std::get<HandshakeResult>(result1).sendingCipherState.cipherKey.raw, std::get<HandshakeResult>(result2).receivingCipherState.cipherKey.raw);
	EXPECT_EQ(std::get<HandshakeResult>(result1).sendingCipherState.nonce, std::get<HandshakeResult>(result2).receivingCipherState.nonce);
}
