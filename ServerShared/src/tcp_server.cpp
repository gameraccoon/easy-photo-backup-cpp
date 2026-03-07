// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "server_shared/tcp_server.h"

#if _WIN32
#include <winsock32.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include <cstring>
#include <format>
#include <thread>

#include "common_shared/network/protocol.h"
#include "common_shared/network/utils.h"
#include "common_shared/serialization/number_serialization.h"
#include "common_shared/template_utils.h"

#include "server_shared/request_answers.h"
#include "server_shared/requests.h"

namespace TcpServer
{
	static void handleClient(const int socket, sockaddr clientAddr, socklen_t clientAddrLen)
	{
		// we need to make sure to have a timeout to not get DOS as soon as a couple of connections hangs
		// we should have a shorter timeout now and increase it when we authentificate the user for the file transfer
		// we may rethink this value if we are going to allow opening this service be accessed through direct connections over web
		if (const auto result = Network::setSocketTimeout(socket, SO_RCVTIMEO, 0, 100000); result.has_value())
		{
			return;
		}

		if (const auto result = Network::setSocketTimeout(socket, SO_SNDTIMEO, 0, 100000); result.has_value())
		{
			return;
		}

		constexpr size_t BUFFER_SIZE = 1024;
		std::array<std::byte, BUFFER_SIZE> buffer;
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

		if (Serialization::readUint16(buffer[0], buffer[1]) != std::optional(Protocol::NetworkProtocolVersion))
		{
			// it is assumed that the server is updated rarely while the client is updated often
			// therefore the server doesn't need to support older client versions
			return;
		}

		auto request = Requests::parseRequest(static_cast<std::byte>(buffer[2]), std::span(std::bit_cast<std::byte*>(buffer.data() + 3), std::bit_cast<std::byte*>(buffer.data() + readBytes)));

		std::visit(
			VisitLambda{
				[](const Requests::RequestReadError&&) {},
				[socket](const Requests::GetServerName&&) {
					RequestAnswers::sendRequestAnswer(
						socket,
						RequestAnswers::AnswerGetServerName{
							.serverName = std::string("test server"),
						}
					);
				} },
			std::move(request)
		);
	}

	std::optional<std::string> runServer(const char* interfaceAddressStr, const Network::AddressType addressType, std::promise<uint16_t>& portPromise)
	{
		std::variant<int, std::string> createSocketResult = createSocket(Network::SocketType::Tcp, addressType);
		if (std::holds_alternative<std::string>(createSocketResult))
		{
			return std::get<std::string>(createSocketResult);
		}

		const Network::AutoclosingSocket socket = Network::AutoclosingSocket(std::get<int>(std::move(createSocketResult)));

		if (auto result = Network::setSocketOption(socket, SO_REUSEADDR); result.has_value())
		{
			return result;
		}

		if (auto result = Network::setSocketOption(socket, SO_REUSEPORT); result.has_value())
		{
			return result;
		}

		if (auto result = Network::bindSocket(socket, interfaceAddressStr, addressType, 0); result.has_value())
		{
			return result;
		}

		auto socketPortResult = Network::getSocketPort(socket);
		if (std::holds_alternative<std::string>(socketPortResult))
		{
			return std::get<std::string>(socketPortResult);
		}

		portPromise.set_value(std::get<uint16_t>(socketPortResult));

		constexpr int MAX_QUEUED_REQUESTS = 4;
		if (const int result = listen(socket, MAX_QUEUED_REQUESTS); result == -1)
		{
			return std::format("Could not start listening to TCP socket, error code {} '{}'.", errno, strerror(errno));
		}

		sockaddr clientAddr;
		socklen_t clientAddrLen = sizeof(sockaddr);
		while (true)
		{
			const int connectionSocket = accept(socket, &clientAddr, &clientAddrLen);
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
