// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "client_shared/send_files_interactive_request.h"

#include "common_shared/cryptography/noise/noise_kk_handshake.h"
#include "common_shared/cryptography/primitives/dh_functions.h"
#include "common_shared/debug/assert.h"
#include "common_shared/debug/log.h"
#include "common_shared/network/protocol.h"
#include "common_shared/network/utils.h"
#include "common_shared/serialization/number_serialization.h"

#include "client_shared/client_storage.h"

namespace Requests
{
	bool processKkHandshake(Network::RawSocket socket, ClientStorage& clientStorage, const std::string& serverName, Noise::CipherStateSending& outSendingCipherState, Noise::CipherStateReceiving& outReceivingCipherState)
	{
		using namespace Noise;

		constexpr size_t FirstMessagePreludeSize = 3;
		constexpr size_t SecondMessagePreludeSize = 1;

		InitiatorHandshakeState handshakeState;

		clientStorage.read([&handshakeState, &serverName](const ClientStorageData& storageData) {
			// TODO: this is very wrong, only for testing
			if (auto it = storageData.pendingConfirmationBindings.find(serverName); it != storageData.pendingConfirmationBindings.end())
			{
				handshakeState = NoiseKK::initializeInitiator(it->second.staticKeys, it->second.remoteStaticKey);
			}
		});

		if (!handshakeState.staticKeys.has_value() || !handshakeState.remoteStaticKey.has_value())
		{
			return false;
		}

		constexpr size_t BufferSize = SecondMessagePreludeSize + DHLEN + DHLEN + CipherAuthDataSize;
		std::array<std::byte, BufferSize> buffer;

		{
			static_assert(buffer.size() >= NoiseKK::Message1ExpectedSize + FirstMessagePreludeSize, "Buffer size is too small to fit the first KK message");

			size_t cursor = 0;

			Serialization::writeUint16(buffer[0], buffer[1], Protocol::NetworkProtocolVersion);
			buffer[2] = static_cast<std::byte>(Protocol::RequestId::SendFiles);
			cursor += FirstMessagePreludeSize;

			NoiseKK::AppendHandshakeMessage1Result result = NoiseKK::appendHandshakeMessage1(
				handshakeState,
				buffer,
				cursor
			);

			if (result.has_value())
			{
				reportDebugError("First KK message was not created correctly {}", static_cast<int>(*result));
				return false;
			}

			if (cursor != NoiseKK::Message1ExpectedSize + FirstMessagePreludeSize)
			{
				reportDebugError("First KK message had unexpected size {}", cursor);
				return false;
			}

			const auto sendResult = Network::send(socket, std::span<std::byte>(buffer.data(), cursor));
			if (sendResult.has_value())
			{
				reportDebugError("Could not send the first KK message");
				return false;
			}
		}

		{
			static_assert(buffer.size() >= NoiseKK::Message2ExpectedSize + SecondMessagePreludeSize, "Buffer size is too small to fit the second KK message");

			size_t readBytes = 0;
			if (auto result = Network::recv(socket, buffer, readBytes); result.has_value())
			{
				reportDebugError("Could not recv the second KK message: {}", *result);
				return false;
			}

			if (readBytes != NoiseKK::Message2ExpectedSize + SecondMessagePreludeSize)
			{
				reportDebugError("Unexpected message size for the second KK message {}", readBytes);
				return false;
			}

			if (buffer[0] != static_cast<std::byte>(Protocol::RequestAnswerId::SendFiles))
			{
				reportDebugError("Unexpected second KK message prelude {}", static_cast<uint8_t>(buffer[0]));
				return false;
			}

			size_t cursor = SecondMessagePreludeSize;
			NoiseKK::ProcessHandshakeMessage2Result result = NoiseKK::processHandshakeMessage2(
				std::move(handshakeState),
				buffer,
				cursor
			);

			if (cursor != readBytes)
			{
				reportDebugError("We read unexpected number of bytes for the second KK handshake message {} {}", readBytes, cursor);
				return false;
			}

			if (std::holds_alternative<NoiseKK::HandshakeResult>(result))
			{
				if (std::holds_alternative<NoiseKK::HandshakeResult>(result))
				{
					outSendingCipherState = std::move(std::get<NoiseKK::HandshakeResult>(result).sendingCipherState);
					outReceivingCipherState = std::move(std::get<NoiseKK::HandshakeResult>(result).receivingCipherState);
					return true;
				}
			}
		}

		return false;
	}

	RequestAnswers::RequestAnswer sendAndProcessSendFilesInteractiveRequest(Network::RawSocket socket, ClientStorage& storage, const std::string& serverName)
	{
		Noise::CipherStateSending sendingCipherState;
		Noise::CipherStateReceiving receivingCipherState;
		if (!processKkHandshake(socket, storage, serverName, sendingCipherState, receivingCipherState))
		{
			reportDebugError("Failed to process KK handshake");
			return RequestAnswers::ErrorNoHandling{};
		}

		{
			std::array<std::byte, 4 + Cryptography::CipherAuthDataSize> buffer;
			buffer[0] = static_cast<std::byte>('a');
			buffer[1] = static_cast<std::byte>('b');
			buffer[2] = static_cast<std::byte>('c');
			buffer[3] = static_cast<std::byte>('d');

			const auto sendResult = Network::sendEncrypted(socket, buffer, 4, sendingCipherState);
			if (sendResult.has_value())
			{
				reportDebugError("Could not send the test encrypted message: {}", *sendResult);
			}
		}

		{
			std::array<std::byte, 4 + Cryptography::CipherAuthDataSize> buffer;
			size_t readBytes = 0;
			if (auto result = Network::recvEncrypted(socket, buffer, readBytes, receivingCipherState); result.has_value())
			{
				reportDebugError("Could not read test message: {}", *result);
				return RequestAnswers::ErrorNoHandling{};
			}

			Debug::Log::printDebug("Received message: " + std::string(reinterpret_cast<const char*>(buffer.data()), readBytes));
		}

		return Protocol::RequestAnswers::SendFiles{};
	}
} // namespace Requests
