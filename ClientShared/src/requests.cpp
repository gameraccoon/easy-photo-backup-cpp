// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "client_shared/requests.h"

#if _WIN32
#include <winsock32.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include <algorithm>
#include <cstring>
#include <format>
#include <span>

#include "common_shared/debug/assert.h"
#include "common_shared/network/protocol.h"
#include "common_shared/serialization/number_serialization.h"
#include "common_shared/template_utils.h"

namespace Requests
{
	static RequestAnswers::RequestAnswer readRequestAnswer(Protocol::Request request, std::byte answerId, const std::span<std::byte>& answerData)
	{
		using namespace RequestAnswers;

		switch (request)
		{
		case Protocol::Request::GetServerName: {
			if (answerId == static_cast<std::byte>(Protocol::RequestAnswer::AnswerGetServerName))
			{
				if (answerData.size() < 1)
				{
					reportDebugError("No size provided in AnswerGetServerName");
					return RequestAnswers::Error{ "No size provided in AnswerGetServerName" };
				}

				const size_t nameSize = static_cast<size_t>(answerData[0]);

				if (answerData.size() != nameSize + 1)
				{
					reportDebugError("Unexpected answer size for AnswerGetServerName {} for name size {}", answerData.size(), nameSize);
					return RequestAnswers::Error{ std::format("Unexpected answer size for AnswerGetServerName {} for name size {}", answerData.size(), nameSize) };
				}

				if (nameSize > Protocol::MaxServerNameSize)
				{
					reportDebugError("Too long server name in AnswerGetServerName: {}", nameSize);
					return RequestAnswers::Error{ std::format("Too long server name in AnswerGetServerName: {}", nameSize) };
				}
				RequestAnswers::AnswerGetServerName answer;
				answer.name.reserve(answerData.size());
				std::copy(std::bit_cast<char*>(answerData.data() + 1), std::bit_cast<char*>(answerData.data() + nameSize + 1), std::back_inserter(answer.name));
				return answer;
			}
			break;
		}
		}

		reportDebugError("Unknown answer {} to request {}", static_cast<int>(answerId), static_cast<int>(request));
		return RequestAnswers::Error{ std::format("Unknown answer {} to request {}", static_cast<int>(answerId), static_cast<int>(request)) };
	}

	RequestAnswers::RequestAnswer sendAndProcessRequest(const char* serverAddress, const Network::AddressType serverAddressType, const int port, Request&& request)
	{
		std::variant<int, std::string> createSocketResult = Network::createSocket(Network::SocketType::Tcp, serverAddressType);
		if (std::holds_alternative<std::string>(createSocketResult))
		{
			reportDebugError("Could not create a TCP socket to send a request from client");
			return RequestAnswers::Error{ std::get<std::string>(createSocketResult) };
		}

		const Network::AutoclosingSocket socket = Network::AutoclosingSocket(std::get<int>(std::move(createSocketResult)));

		if (const auto result = Network::setSocketTimeout(socket, SO_RCVTIMEO, 1, 0); result.has_value())
		{
			reportDebugError("Could not set SO_RCVTIMEO to a client TCP socket");
			return RequestAnswers::Error{ *result };
		}
		if (const auto result = Network::setSocketTimeout(socket, SO_SNDTIMEO, 1, 0); result.has_value())
		{
			reportDebugError("Could not set SO_SNDTIMEO to a client TCP socket");
			return RequestAnswers::Error{ *result };
		}

		if (const auto result = Network::bindSocket(socket, nullptr, serverAddressType, 0); result.has_value())
		{
			reportDebugError("Could not bind client TCP socket");
			return RequestAnswers::Error{ *result };
		}

		if (const auto result = Network::connectToServer(socket, serverAddress, serverAddressType, port); result.has_value())
		{
			return RequestAnswers::Error{ *result };
		}

		constexpr size_t MAX_MESSAGE_SIZE = 1024;
		std::array<std::byte, MAX_MESSAGE_SIZE> buffer;
		size_t messageSize = 3;
		bool expectsAnswer = false;
		std::optional<Protocol::Request> requestId;

		std::visit(
			VisitLambda{
				[&expectsAnswer, &requestId](Requests::RequestGetServerName&&) {
					requestId = Protocol::Request::GetServerName;
					expectsAnswer = true;
				},
			},
			std::move(request)
		);

		if (!requestId.has_value())
		{
			reportReleaseError("No request id provided, can't send the request");
			return RequestAnswers::LogicalError{ "No request id provided, can't send the request" };
		}

		Serialization::writeUint16(buffer[0], buffer[1], Protocol::NetworkProtocolVersion);
		buffer[2] = static_cast<std::byte>(*requestId);

		if (messageSize > MAX_MESSAGE_SIZE)
		{
			reportReleaseError("Message size is bigger than MAX_MESSAGE_SIZE: {}", messageSize);
			return RequestAnswers::LogicalError{ std::format("Message size is bigger than MAX_MESSAGE_SIZE: {}", messageSize) };
		}

		if (auto result = Network::send(socket, std::span(buffer.data(), messageSize)); result.has_value())
		{
			return RequestAnswers::Error{ *result };
		}

		if (expectsAnswer)
		{
			// we assume that the message wasn't fragmented, as we don't know what size should it be
			// and can't yet process it in parts
			if (auto result = Network::recv(socket, buffer, messageSize); result.has_value())
			{
				return RequestAnswers::Error{ *result };
			}

			return readRequestAnswer(*requestId, buffer[0], std::span<std::byte>{ buffer.data() + 1, messageSize - 1 });
		}

		return RequestAnswers::ExpectedNoAnswer{};
	}
} // namespace Requests
