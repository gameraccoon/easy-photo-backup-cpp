// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "server_shared/tcp_server.h"

#include <array>
#include <cstring>
#include <format>
#include <functional>
#include <thread>
#include <unordered_map>

#include "common_shared/debug/assert.h"
#include "common_shared/network/protocol.h"
#include "common_shared/network/raw_sockets.h"
#include "common_shared/network/utils.h"
#include "common_shared/serialization/number_serialization.h"
#include "common_shared/template_utils.h"

#include "server_shared/pairing_interactive_request.h"
#include "server_shared/request_answers.h"
#include "server_shared/requests.h"

namespace TcpServer
{
	static void handleClient(const Network::RawSocket socket, sockaddr /*clientAddr*/, socklen_t /*clientAddrLen*/)
	{
		// we need to make sure to have a timeout to not get DOS as soon as a couple of connections hangs
		// we should have a shorter timeout now and increase it when we authentificate the user for the file transfer
		// we may rethink this value if we are going to allow opening this service be accessed through direct connections over web
		if (const auto result = Network::setSocketTimeout(socket, SO_RCVTIMEO, 0, 100000); result.has_value())
		{
			reportDebugError("Could not set SO_RCVTIMEO to a connection socket");
			return;
		}

		if (const auto result = Network::setSocketTimeout(socket, SO_SNDTIMEO, 0, 100000); result.has_value())
		{
			reportDebugError("Could not set SO_SNDTIMEO to a connection socket");
			return;
		}

		constexpr size_t BUFFER_SIZE = Protocol::MaxRequestSize;
		std::array<std::byte, BUFFER_SIZE> buffer = {};
		size_t readBytes = 0;
		if (auto result = Network::recv(socket, buffer, readBytes); result.has_value())
		{
			return;
		}

		// each request needs to be at least three bytes (protocol version (2) and request ID (1))
		if (readBytes < 3)
		{
			return;
		}

		// GetProtocolVersion is a special case that doesn't require version match
		// this is to allow newer and older clients to request the version of the server
		// this request guaranteed to not change between versions
		if (buffer[2] == static_cast<std::byte>(Protocol::RequestId::GetProtocolVersion))
		{
			RequestAnswers::sendRequestAnswer(
				socket,
				RequestAnswers::GetProtocolVersion{
					.protocolVersion = Protocol::NetworkProtocolVersion,
				}
			);
			return;
		}

		const uint16_t protocolVerstion = Serialization::readUint16(buffer[0], buffer[1]);
		if (protocolVerstion != std::optional(Protocol::NetworkProtocolVersion))
		{
			// it is assumed that the server is updated rarely while the client is updated often
			// therefore the server doesn't need to support older client versions
			reportDebugError("An old client version tried to connect: {}", protocolVerstion);
			RequestAnswers::sendRequestAnswer(
				socket,
				RequestAnswers::UnsupportedProtocolVersion{
					.firstSupportedProtocolVersion = Protocol::NetworkProtocolVersion,
				}
			);
			return;
		}

		const std::byte requestIdByte = buffer[2];

		if (std::ranges::find(Protocol::InteractiveRequests, requestIdByte) != Protocol::InteractiveRequests.end())
		{
			// interactive requests
			if (requestIdByte == static_cast<std::byte>(Protocol::RequestId::Pair))
			{
				Requests::processPairingInteractiveRequest(buffer, readBytes, socket);
			}
			else
			{
				reportDebugError("Unknown interactive request id {}", static_cast<int>(requestIdByte));
				return;
			}
		}
		else
		{
			// non-interactive requests
			auto request = Requests::parseRequest(requestIdByte, std::span(buffer.data() + 3, buffer.data() + readBytes));

			std::visit(
				VisitLambda{
					[](const Requests::RequestReadError&&) {},
					[](const Requests::GetProtocolVersion&&) {
						// should be already handled above
						reportFatalReleaseError("unreachable code");
					},
					[socket](const Requests::GetServerName&&) {
						RequestAnswers::sendRequestAnswer(
							socket,
							RequestAnswers::GetServerName{
								.serverName = std::string("test server"),
							}
						);
					} },
				std::move(request)
			);
		}
	}

	std::optional<std::string> runServer(const char* interfaceAddressStr, const Network::AddressType addressType, std::promise<uint16_t>& portPromise)
	{
		std::variant<Network::RawSocket, std::string> createSocketResult = createSocket(Network::SocketType::Tcp, addressType);
		if (std::holds_alternative<std::string>(createSocketResult))
		{
			return std::get<std::string>(createSocketResult);
		}

		const Network::AutoclosingSocket socket = Network::AutoclosingSocket(std::get<Network::RawSocket>(std::move(createSocketResult)));

		if (auto result = Network::setSocketOption(socket, SO_REUSEADDR); result.has_value())
		{
			reportDebugError("Could not set SO_REUSEADDR on the server TCP socket");
			return result;
		}

#if !_WIN32
		if (auto result = Network::setSocketOption(socket, SO_REUSEPORT); result.has_value())
		{
			reportDebugError("Could not set SO_REUSEPORT on the server TCP socket");
			return result;
		}
#endif

		if (auto result = Network::bindSocket(socket, interfaceAddressStr, addressType, 0); result.has_value())
		{
			reportDebugError("Could not bind a server TCP socket");
			return result;
		}

		auto socketPortResult = Network::getSocketPort(socket);
		if (std::holds_alternative<std::string>(socketPortResult))
		{
			reportDebugError("Could not get server port from the cocket");
			return std::get<std::string>(socketPortResult);
		}

		portPromise.set_value(std::get<uint16_t>(socketPortResult));

		constexpr int MAX_QUEUED_REQUESTS = 4;
		if (const int result = listen(socket, MAX_QUEUED_REQUESTS); result == -1)
		{
			reportDebugError("Could not start listening to TCP socket, error code {}.", errno);
			return std::format("Could not start listening to TCP socket, error code {}.", errno);
		}

		sockaddr clientAddr;
		socklen_t clientAddrLen = sizeof(sockaddr);
		while (true)
		{
			const Network::RawSocket connectionSocket = accept(socket, &clientAddr, &clientAddrLen);
			if (connectionSocket == -1)
			{
				break;
			}

			// ToDo: creating new threads here is silly, we need to use a thread pool
			// to both not spend extra time on spinning up threads for small requests
			// and avoid getting DOSed simply by spamming small requests
			std::thread([connectionSocket, clientAddr, clientAddrLen] {
				Network::AutoclosingSocket socketGuard(connectionSocket);
				handleClient(connectionSocket, clientAddr, clientAddrLen);
			}).detach();
		}

		return std::nullopt;
	}
} // namespace TcpServer
