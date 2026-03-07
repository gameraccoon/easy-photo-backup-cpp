// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "server_shared/request_answers.h"

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
#include <optional>

#include "common_shared/network/utils.h"
#include "common_shared/template_utils.h"

namespace RequestAnswers
{
	std::optional<std::string> sendRequestAnswer(int socket, RequestAnswer&& requestAnswer)
	{
		return std::visit(
			VisitLambda{
				[socket](GetServerName&& response) -> std::optional<std::string> {
					std::array<std::byte, Protocol::MaxServerNameSize + 2> buffer;
					const size_t nameSize = std::min(response.serverName.size(), static_cast<size_t>(Protocol::MaxServerNameSize));
					buffer[0] = static_cast<std::byte>(Protocol::RequestAnswerId::AnswerGetServerName);
					buffer[1] = static_cast<std::byte>(nameSize);
					std::copy(std::bit_cast<std::byte*>(response.serverName.data()), std::bit_cast<std::byte*>(response.serverName.data() + nameSize), buffer.data() + 2);
					size_t messageSize = nameSize + 2;

					if (auto result = Network::send(socket, std::span(buffer.data(), messageSize)); result.has_value())
					{
						return *result;
					}
					return std::nullopt;
				},
			},
			std::move(requestAnswer)
		);
	}
} // namespace RequestAnswers
