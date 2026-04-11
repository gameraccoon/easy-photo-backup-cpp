// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "client_shared/pairing_interactive_requests.h"

#include "common_shared/cryptography/noise/noise_xx_handshake.h"
#include "common_shared/cryptography/primitives/dh_functions.h"
#include "common_shared/debug/assert.h"
#include "common_shared/network/utils.h"

namespace Requests
{
	bool sendAndProcessPairingInteractiveRequest(Network::RawSocket socket)
	{
		using namespace Noise;

		const Keypair staticKeys = Cryptography::generateKeypair_x25519();

		InitiatorHandshakeState handshakeState = NoiseXX::initializeInitiator(staticKeys);

		std::array<std::byte, DHLEN + DHLEN + CipherAuthDataSize> buffer;

		{
			size_t cursor = 1;
			NoiseXX::AppendHandshakeMessage1Result result = NoiseXX::appendHandshakeMessage1(
				handshakeState,
				std::span<std::byte>(buffer.data(), buffer.data() + NoiseXX::Message1ExpectedSize),
				cursor
			);

			if (result.has_value())
			{
				reportDebugError("First XX message was not created correctly {}", static_cast<int>(*result));
				return false;
			}

			if (cursor != NoiseXX::Message1ExpectedSize)
			{
				reportDebugError("First XX message had unexpected size {}", cursor);
				return false;
			}

			const auto sendResult = Network::send(socket, buffer);
			if (sendResult.has_value())
			{
				reportDebugError("Could not send the first XX message");
			}
		}

		{
			size_t readBytes = 0;
			if (auto result = Network::recv(socket, buffer, readBytes); result.has_value())
			{
				reportDebugError("Could not read the second XX message");
				return false;
			}

			if (readBytes != NoiseXX::Message2ExpectedSize)
			{
				reportDebugError("Unexpected message size for the second XX message {}", readBytes);
				return false;
			}

			size_t cursor = 0;
			const NoiseXX::ProcessHandshakeMessage2Result result = NoiseXX::processHandshakeMessage2(
				handshakeState,
				std::span<std::byte>(buffer.begin(), buffer.begin() + readBytes),
				cursor
			);

			if (result.has_value())
			{
				reportDebugError("Did not process the second XX message correctly {}", static_cast<int>(*result));
				return false;
			}

			if (cursor != readBytes)
			{
				reportDebugError("We read unexpected number of bytes for the second XX handshake message {} {}", readBytes, cursor);
				return false;
			}
		}

		{
			if (buffer.size() < NoiseXX::Message2ExpectedSize)
			{
				reportDebugError("Buffer size is too small to fit third XX message {}", buffer.size());
				return false;
			}

			size_t cursor = 0;
			const NoiseXX::AppendHandshakeMessage3Result result = NoiseXX::appendHandshakeMessage3(
				std::move(handshakeState),
				std::span<std::byte>(buffer.begin(), buffer.begin() + NoiseXX::Message2ExpectedSize),
				cursor
			);

			if (std::holds_alternative<MessageWriteError>(result))
			{
				reportDebugError("Did not append the third XX message correctly {}", static_cast<int>(std::get<MessageWriteError>(result)));
				return false;
			}

			if (cursor != NoiseXX::Message3ExpectedSize)
			{
				reportDebugError("Third XX message had unexpected size {}", cursor);
				return false;
			}

			const auto sendResult = Network::send(socket, buffer);
			if (sendResult.has_value())
			{
				reportDebugError("Could not send the third XX message");
				return false;
			}

			if (std::holds_alternative<NoiseXX::HandshakeResult>(result))
			{
				// std::get<NoiseXX::HandshakeResult>(result).handshakeHash;
				// std::get<NoiseXX::HandshakeResult>(result).remoteStaticKey;
				// staticKeys;
			}
		}

		return true;
	}
} // namespace Requests
