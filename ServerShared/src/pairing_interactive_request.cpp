// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "server_shared/pairing_interactive_request.h"

#include "common_shared/cryptography/noise/noise_xx_handshake.h"
#include "common_shared/cryptography/primitives/dh_functions.h"
#include "common_shared/debug/assert.h"
#include "common_shared/network/raw_sockets.h"

namespace Requests
{
	void processPairingInteractiveRequest(std::array<std::byte, Protocol::MaxRequestSize>& buffer, size_t readBytes, const Network::RawSocket socket)
	{
		using namespace Noise;

		constexpr size_t FirstMessagePreludeSize = 3;
		constexpr size_t SecondMessagePreludeSize = 1;

		const Cryptography::Keypair staticKeys = Cryptography::generateKeypair_x25519();
		ResponderHandshakeState handshakeState = NoiseXX::initializeResponder(staticKeys);

		{
			assertFatalRelease(buffer.size() >= NoiseXX::Message1ExpectedSize + FirstMessagePreludeSize, "Buffer size is too small to fit the first XX message");

			if (readBytes != NoiseXX::Message1ExpectedSize + FirstMessagePreludeSize)
			{
				reportDebugError("Unexpected message size for the first XX message {}", readBytes);
				return;
			}

			size_t cursor = FirstMessagePreludeSize;
			const NoiseXX::ProcessHandshakeMessage1Result result = NoiseXX::processHandshakeMessage1(
				handshakeState,
				buffer,
				cursor
			);

			if (result.has_value())
			{
				reportDebugError("Did not process the first XX message correctly {}", static_cast<int>(*result));
				return;
			}

			if (cursor != readBytes)
			{
				reportDebugError("We read unexpected number of bytes for the first XX handshake message {} {}", readBytes, cursor);
				return;
			}
		}

		// increase the timeouts for the rest of the handshake
		if (const auto result = Network::setSocketTimeout(socket, SO_RCVTIMEO, 1, 0); result.has_value())
		{
			reportDebugError("Could not set SO_RCVTIMEO to a connection socket");
			return;
		}

		if (const auto result = Network::setSocketTimeout(socket, SO_SNDTIMEO, 1, 0); result.has_value())
		{
			reportDebugError("Could not set SO_SNDTIMEO to a connection socket");
			return;
		}

		{
			assertFatalRelease(buffer.size() >= NoiseXX::Message2ExpectedSize + SecondMessagePreludeSize, "Buffer size is too small to fit the second XX message");

			buffer[0] = static_cast<std::byte>(Protocol::RequestAnswerId::Pair);

			size_t cursor = SecondMessagePreludeSize;
			const NoiseXX::AppendHandshakeMessage2Result result = NoiseXX::appendHandshakeMessage2(
				handshakeState,
				buffer,
				cursor
			);

			if (result.has_value())
			{
				reportDebugError("Did not append the second XX message correctly {}", static_cast<int>(*result));
				return;
			}

			if (cursor != NoiseXX::Message2ExpectedSize + SecondMessagePreludeSize)
			{
				reportDebugError("Second XX message had unexpected size {}", cursor);
				return;
			}

			const auto sendResult = Network::send(socket, buffer);
			if (sendResult.has_value())
			{
				reportDebugError("Could not send the second XX message");
			}
		}

		{
			assertFatalRelease(buffer.size() >= NoiseXX::Message3ExpectedSize, "Buffer size is too small to fit the third XX message");

			if (auto result = Network::recv(socket, buffer, readBytes); result.has_value())
			{
				reportDebugError("Could not recv the third XX message");
				return;
			}

			if (readBytes != NoiseXX::Message3ExpectedSize)
			{
				reportDebugError("Unexpected message size for the third XX message {}", readBytes);
				return;
			}

			size_t cursor = 0;
			const NoiseXX::ProcessHandshakeMessage3Result result = NoiseXX::processHandshakeMessage3(
				std::move(handshakeState),
				std::span<std::byte>(buffer.begin(), buffer.begin() + readBytes),
				cursor
			);

			if (cursor != readBytes)
			{
				reportDebugError("We read unexpected number of bytes for the third XX handshake message {} {}", readBytes, cursor);
				return;
			}

			if (std::holds_alternative<NoiseXX::HandshakeResult>(result))
			{
				// std::get<NoiseXX::HandshakeResult>(result).handshakeHash;
				// std::get<NoiseXX::HandshakeResult>(result).remoteStaticKey;
				// staticKeys
			}
		}
	}
} // namespace Requests
