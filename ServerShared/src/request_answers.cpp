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
#include "common_shared/serialization/number_serialization.h"
#include "common_shared/serialization/string_serialization.h"
#include "common_shared/template_utils.h"

namespace RequestAnswers
{
	std::optional<std::string> sendRequestAnswer(int socket, RequestAnswer&& requestAnswer)
	{
		return std::visit(
			VisitLambda{
				[socket](UnsupportedProtocolVersion&& response) -> std::optional<std::string> {
					// make sure this logic does not change, as this answer is supposed to be the same across all versions
					// in order for it to work
					std::array<std::byte, 3> buffer;
					buffer[0] = static_cast<std::byte>(Protocol::RequestAnswerId::UnsupportedProtocolVersion);
					Serialization::writeUint16(buffer[1], buffer[2], response.firstSupportedProtocolVersion);

					return Network::send(socket, buffer);
				},
				[socket](GetProtocolVersion&& response) -> std::optional<std::string> {
					// make sure this logic does not change, as this answer is supposed to be the same across all versions
					// in order for it to work
					std::array<std::byte, 3> buffer;
					buffer[0] = static_cast<std::byte>(Protocol::RequestAnswerId::GetProtocolVersion);
					Serialization::writeUint16(buffer[1], buffer[2], response.protocolVersion);

					return Network::send(socket, buffer);
				},
				[socket](GetServerName&& response) -> std::optional<std::string> {
					std::array<std::byte, Protocol::MaxServerNameSize + 2> buffer;
					const size_t nameSize = std::min(response.serverName.size(), static_cast<size_t>(Protocol::MaxServerNameSize));
					buffer[0] = static_cast<std::byte>(Protocol::RequestAnswerId::GetServerName);
					buffer[1] = static_cast<std::byte>(nameSize);
					std::copy(std::bit_cast<std::byte*>(response.serverName.data()), std::bit_cast<std::byte*>(response.serverName.data() + nameSize), buffer.data() + 2);
					const size_t messageSize = nameSize + 2;

					return Network::send(socket, std::span(buffer.data(), messageSize));
				},
			},
			std::move(requestAnswer)
		);
	}
} // namespace RequestAnswers
