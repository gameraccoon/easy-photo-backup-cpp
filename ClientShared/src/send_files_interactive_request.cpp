// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "client_shared/send_files_interactive_request.h"

#include "common_shared/cryptography/noise/noise_kk_handshake.h"
#include "common_shared/debug/assert.h"
#include "common_shared/network/protocol.h"
#include "common_shared/network/utils.h"
#include "common_shared/serialization/number_serialization.h"

#include "client_shared/client_storage.h"
#include "client_shared/file_send_utils.h"

namespace Requests
{
	bool processKkHandshake(Network::RawSocket socket, ClientStorage& clientStorage, const std::string& serverName, Noise::CipherStateSending& outSendingCipherState, Noise::CipherStateReceiving& outReceivingCipherState) noexcept
	{
		using namespace Noise;

		constexpr size_t FirstMessagePreludeSize = sizeof(Protocol::NetworkProtocolVersion) + sizeof(Protocol::RequestId);
		constexpr size_t SecondMessagePreludeSize = sizeof(Protocol::RequestAnswerId);

		InitiatorHandshakeState handshakeState;

		clientStorage.read([&handshakeState, &serverName](const ClientStorageData& storageData) {
			if (auto it = storageData.confirmedServerBindings.find(serverName); it != storageData.confirmedServerBindings.end())
			{
				handshakeState = NoiseKK::initializeInitiator(it->second.staticKeys, it->second.remoteStaticKey);
			}
		});

		if (!handshakeState.staticKeys.has_value() || !handshakeState.remoteStaticKey.has_value())
		{
			return false;
		}

		constexpr size_t BufferSize = SecondMessagePreludeSize + DHLEN + DHLEN + CipherAuthDataSize;
		Cryptography::ByteSequence<Cryptography::ByteSequenceTag::TempInternalBuffer, BufferSize> buffer;

		{
			static_assert(buffer.size() >= NoiseKK::Message1ExpectedSize + FirstMessagePreludeSize, "Buffer size is too small to fit the first KK message");

			size_t cursor = 0;

			Serialization::writeUint16(buffer.raw[0], buffer.raw[1], Protocol::NetworkProtocolVersion);
			buffer.raw[2] = static_cast<std::byte>(Protocol::RequestId::SendFiles);
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

			const auto sendResult = Network::send(socket, std::span<std::byte>(buffer.raw.data(), cursor));
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

			if (buffer.raw[0] != static_cast<std::byte>(Protocol::RequestAnswerId::SendFiles))
			{
				reportDebugError("Unexpected second KK message prelude {}", static_cast<uint8_t>(buffer.raw[0]));
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

	RequestAnswers::RequestAnswer sendAndProcessSendFilesInteractiveRequest(Network::RawSocket socket, ClientStorage& storage, const std::string& serverName) noexcept
	{
		Noise::CipherStateSending sendingCipherState;
		Noise::CipherStateReceiving receivingCipherState;
		if (!processKkHandshake(socket, storage, serverName, sendingCipherState, receivingCipherState))
		{
			reportDebugError("Failed to process KK handshake");
			return RequestAnswers::ErrorNoHandling{};
		}

		FileSendUtils::sendDirectory(std::filesystem::path("./client_files_to_send"), socket, sendingCipherState, receivingCipherState);

		return Protocol::RequestAnswers::SendFiles{};
	}
} // namespace Requests
