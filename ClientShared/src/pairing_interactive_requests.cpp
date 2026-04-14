// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "client_shared/pairing_interactive_requests.h"

#include "common_shared/cryptography/noise/noise_xx_handshake.h"
#include "common_shared/cryptography/primitives/dh_functions.h"
#include "common_shared/debug/assert.h"
#include "common_shared/network/protocol.h"
#include "common_shared/network/utils.h"
#include "common_shared/serialization/number_serialization.h"

namespace Requests
{
	bool sendAndProcessPairingInteractiveRequest(Network::RawSocket socket, ClientStorage& storage, std::string_view serverName)
	{
		using namespace Noise;

		constexpr size_t FirstMessagePreludeSize = 3;
		constexpr size_t SecondMessagePreludeSize = 1;

		Keypair staticKeys = Cryptography::generateKeypair_x25519();

		InitiatorHandshakeState handshakeState = NoiseXX::initializeInitiator(staticKeys);

		constexpr size_t BufferSize = SecondMessagePreludeSize + DHLEN + DHLEN + CipherAuthDataSize;
		std::array<std::byte, BufferSize> buffer;

		{
			static_assert(buffer.size() >= NoiseXX::Message1ExpectedSize + FirstMessagePreludeSize, "Buffer size is too small to fit the first XX message");

			size_t cursor = 0;

			Serialization::writeUint16(buffer[0], buffer[1], Protocol::NetworkProtocolVersion);
			buffer[2] = static_cast<std::byte>(Protocol::RequestId::Pair);
			cursor += FirstMessagePreludeSize;

			NoiseXX::AppendHandshakeMessage1Result result = NoiseXX::appendHandshakeMessage1(
				handshakeState,
				buffer,
				cursor
			);

			if (result.has_value())
			{
				reportDebugError("First XX message was not created correctly {}", static_cast<int>(*result));
				return false;
			}

			if (cursor != NoiseXX::Message1ExpectedSize + FirstMessagePreludeSize)
			{
				reportDebugError("First XX message had unexpected size {}", cursor);
				return false;
			}

			const auto sendResult = Network::send(socket, std::span<std::byte>(buffer.data(), cursor));
			if (sendResult.has_value())
			{
				reportDebugError("Could not send the first XX message");
			}
		}

		{
			static_assert(buffer.size() >= NoiseXX::Message2ExpectedSize + SecondMessagePreludeSize, "Buffer size is too small to fit the second XX message");

			size_t readBytes = 0;
			if (auto result = Network::recv(socket, buffer, readBytes); result.has_value())
			{
				reportDebugError("Could not recv the second XX message");
				return false;
			}

			if (readBytes != NoiseXX::Message2ExpectedSize + SecondMessagePreludeSize)
			{
				reportDebugError("Unexpected message size for the second XX message {}", readBytes);
				return false;
			}

			if (buffer[0] != static_cast<std::byte>(Protocol::RequestAnswerId::Pair))
			{
				reportDebugError("Unexpected second XX message prelude {}", static_cast<uint8_t>(buffer[0]));
				return false;
			}

			size_t cursor = SecondMessagePreludeSize;
			const NoiseXX::ProcessHandshakeMessage2Result result = NoiseXX::processHandshakeMessage2(
				handshakeState,
				buffer,
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
			static_assert(buffer.size() >= NoiseXX::Message3ExpectedSize, "Buffer size is too small to fit the third XX message");

			size_t cursor = 0;
			NoiseXX::AppendHandshakeMessage3Result result = NoiseXX::appendHandshakeMessage3(
				std::move(handshakeState),
				buffer,
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

			const auto sendResult = Network::send(socket, std::span<std::byte>(buffer.data(), cursor));
			if (sendResult.has_value())
			{
				reportDebugError("Could not send the third XX message");
				return false;
			}

			if (std::holds_alternative<NoiseXX::HandshakeResult>(result))
			{
				storage.mutate([&result, &staticKeys, &serverName](ClientStorageData& storage) {
					storage.pendingConfirmationBindings.emplace(
						serverName,
						ClientStorageData::PendingServerBinding{
							.remoteStaticKey = std::move(std::get<NoiseXX::HandshakeResult>(result).remoteStaticKey),
							.staticKeys = std::move(staticKeys),
							.handshakeHash = std::move(std::get<NoiseXX::HandshakeResult>(result).handshakeHash),
							.expiryTime = std::chrono::system_clock::now(),
						}
					);
				});
			}
		}

		return true;
	}
} // namespace Requests
