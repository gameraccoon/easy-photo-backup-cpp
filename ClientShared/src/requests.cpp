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
					return RequestAnswers::Error{ "No size provided in AnswerGetServerName" };
				}

				const size_t nameSize = static_cast<size_t>(answerData[0]);

				if (answerData.size() != nameSize + 1)
				{
					return RequestAnswers::Error{ std::format("Unexpected answer size for AnswerGetServerName {} for name size {}", answerData.size(), nameSize) };
				}

				if (nameSize > Protocol::MaxServerNameSize)
				{
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

		return RequestAnswers::Error{ std::format("Unknown answer {} to request {}", static_cast<int>(answerId), static_cast<int>(request)) };
	}

	RequestAnswers::RequestAnswer sendAndProcessRequest(const char* serverAddress, const Network::AddressType serverAddressType, const int port, Request&& request)
	{
		std::variant<int, std::string> createSocketResult = Network::createSocket(Network::SocketType::Tcp, serverAddressType);
		if (std::holds_alternative<std::string>(createSocketResult))
		{
			return RequestAnswers::Error{ std::get<std::string>(createSocketResult) };
		}

		const Network::AutoclosingSocket socket = Network::AutoclosingSocket(std::get<int>(std::move(createSocketResult)));

		if (const auto result = Network::setSocketTimeout(socket, SO_RCVTIMEO, 1, 0); result.has_value())
		{
			return RequestAnswers::Error{ *result };
		}
		if (const auto result = Network::setSocketTimeout(socket, SO_SNDTIMEO, 1, 0); result.has_value())
		{
			return RequestAnswers::Error{ *result };
		}

		if (const auto result = Network::bindSocket(socket, nullptr, serverAddressType, 0); result.has_value())
		{
			return RequestAnswers::Error{ *result };
		}

		if (const auto result = Network::connectToServer(socket, serverAddress, serverAddressType, port); result.has_value())
		{
			return RequestAnswers::Error{ *result };
		}

		constexpr size_t MAX_MESSAGE_SIZE = 1024;
		std::byte buffer[MAX_MESSAGE_SIZE];
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
			return RequestAnswers::LogicalError{ "No request id provided, nothing has been sent" };
		}

		Serialization::writeUint16(buffer[0], buffer[1], Protocol::NetworkProtocolVersion);
		buffer[2] = static_cast<std::byte>(*requestId);

		if (messageSize > MAX_MESSAGE_SIZE)
		{
			return RequestAnswers::LogicalError{ std::format("Logical error, message size is bigger than MAX_MESSAGE_SIZE: {}", messageSize) };
		}

		const ssize_t sentSize = send(socket, buffer, messageSize, 0);
		if (sentSize == -1)
		{
			return RequestAnswers::Error{ std::format("Failed to send response to TCP socket, error code {} '{}'.", errno, strerror(errno)) };
		}

		if (sentSize == 0)
		{
			return RequestAnswers::LogicalError{ "Sent size was zero, this is unexpected" };
		}

		if (sentSize < messageSize)
		{
			return RequestAnswers::LogicalError{ std::format("Sent size was less than the message size, this is not expected. Expected: {}, ent: {}", messageSize, sentSize) };
		}

		if (sentSize > messageSize)
		{
			return RequestAnswers::LogicalError{ std::format("Sent size was greater than the message size, this is not expected. Expected: {}, ent: {}", messageSize, sentSize) };
		}

		if (expectsAnswer)
		{
			// we assume that the message wasn't fragmented, as we don't know what size should it be
			// and can't yet process it in parts
			messageSize = recv(socket, buffer, MAX_MESSAGE_SIZE, 0);
			if (messageSize == -1)
			{
				return RequestAnswers::Error{ std::format("Failed to read response from TCP socket, error code {} '{}'.", errno, strerror(errno)) };
			}

			if (messageSize == 0)
			{
				return RequestAnswers::Error{ "Received message size was zero, possibly reached the timeout" };
			}

			if (messageSize > MAX_MESSAGE_SIZE)
			{
				return RequestAnswers::LogicalError{ std::format("Received message size was greater than the max message size, this is not expected: {}", messageSize) };
			}

			return readRequestAnswer(*requestId, buffer[0], std::span<std::byte>{ buffer + 1, messageSize - 1 });
		}

		return RequestAnswers::ExpectedNoAnswer{};
	}
} // namespace Requests
