// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "server_shared/send_files_interactive_request.h"

#include "common_shared/cryptography/noise/noise_kk_handshake.h"
#include "common_shared/debug/assert.h"
#include "common_shared/network/protocol.h"
#include "common_shared/network/raw_sockets.h"

#include "server_shared/file_receive_utils.h"
#include "server_shared/server_storage.h"

namespace Requests
{
	constexpr const int SubsequentMessagesTimeoutSeconds = 1;
	constexpr const int SubsequentMessagesTimeoutMicroseconds = 0;

	bool processKkHandshake(std::span<const std::byte> firstMessage, const Network::RawSocket socket, ServerStorage& storage, const std::string& clientName, Noise::CipherStateSending& outSendingCipherState, Noise::CipherStateReceiving& outReceivingCipherState)
	{
		using namespace Noise;

		constexpr size_t SecondMessagePreludeSize = sizeof(Protocol::RequestAnswerId);

		ResponderHandshakeState handshakeState;

		storage.read([&clientName, &handshakeState](const ServerStorageData& storageData) {
			if (auto it = storageData.confirmedClientBindings.find(clientName); it != storageData.confirmedClientBindings.end())
			{
				// for now only apply first found
				handshakeState = NoiseKK::initializeResponder(it->second.staticKeys, it->second.remoteStaticKey);
				return;
			}
		});

		if (!handshakeState.remoteStaticKey.has_value() || !handshakeState.staticKeys.has_value())
		{
			return false;
		}

		{
			if (firstMessage.size() != NoiseKK::Message1ExpectedSize)
			{
				reportDebugError("Unexpected message size for the first KK message {}", firstMessage.size());
				return false;
			}

			size_t cursor = 0;
			const NoiseKK::ProcessHandshakeMessage1Result result = NoiseKK::processHandshakeMessage1(
				handshakeState,
				firstMessage,
				cursor
			);

			if (result.has_value())
			{
				reportDebugError("Did not process the first KK message correctly {}", static_cast<int>(*result));
				return false;
			}

			if (cursor != firstMessage.size())
			{
				reportDebugError("We read unexpected number of bytes for the first KK handshake message {} {}", firstMessage.size(), cursor);
				return false;
			}
		}

		// increase the timeouts for the rest of the handshake
		if (const auto result = Network::setSocketTimeout(socket, SO_RCVTIMEO, SubsequentMessagesTimeoutSeconds, SubsequentMessagesTimeoutMicroseconds); result.has_value())
		{
			reportDebugError("Could not set SO_RCVTIMEO to a connection socket");
			return false;
		}

		if (const auto result = Network::setSocketTimeout(socket, SO_SNDTIMEO, SubsequentMessagesTimeoutSeconds, SubsequentMessagesTimeoutMicroseconds); result.has_value())
		{
			reportDebugError("Could not set SO_SNDTIMEO to a connection socket");
			return false;
		}

		Cryptography::ByteSequence<Cryptography::ByteSequenceTag::TempInternalBuffer, NoiseKK::Message2ExpectedSize + SecondMessagePreludeSize> buffer;

		{
			assertFatalRelease(buffer.size() >= NoiseKK::Message2ExpectedSize + SecondMessagePreludeSize, "Buffer size is too small to fit the second KK message");

			buffer.raw[0] = static_cast<std::byte>(Protocol::RequestAnswerId::SendFiles);

			size_t cursor = SecondMessagePreludeSize;
			NoiseKK::AppendHandshakeMessage2Result result = NoiseKK::appendHandshakeMessage2(
				std::move(handshakeState),
				buffer,
				cursor
			);

			if (cursor != NoiseKK::Message2ExpectedSize + SecondMessagePreludeSize)
			{
				reportDebugError("Second KK message had unexpected size {}", cursor);
				return false;
			}

			const auto sendResult = Network::send(socket, buffer);
			if (sendResult.has_value())
			{
				reportDebugError("Could not send the second KK message");
				return false;
			}

			if (std::holds_alternative<NoiseKK::HandshakeResult>(result))
			{
				outSendingCipherState = std::move(std::get<NoiseKK::HandshakeResult>(result).sendingCipherState);
				outReceivingCipherState = std::move(std::get<NoiseKK::HandshakeResult>(result).receivingCipherState);
				return true;
			}
		}

		return false;
	}

	void processSendFilesInteractiveRequest(std::span<const std::byte> firstMessage, const Network::RawSocket socket, ServerStorage& storage, const std::string& clientName)
	{
		Noise::CipherStateSending sendingCipherState;
		Noise::CipherStateReceiving receivingCipherState;
		if (!processKkHandshake(firstMessage, socket, storage, clientName, sendingCipherState, receivingCipherState))
		{
			reportDebugError("Could not process KK handshake");
			return;
		}

		FileReceiveUtils::receiveFiles("./server_target_directory", socket, sendingCipherState, receivingCipherState);

		Debug::Log::printDebug("Finished receiving files");
	}
} // namespace Requests
