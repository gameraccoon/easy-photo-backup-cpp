// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include <optional>
#include <string>
#include <variant>

#include "common_shared/network/protocol.h"

namespace RequestAnswers
{
	using namespace Protocol::RequestAnswers;

	using RequestAnswer = std::variant<GetServerName>;

	std::optional<std::string> sendRequestAnswer(int socket, RequestAnswer&& requestAnswer);
} // namespace RequestAnswers
