// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include <optional>
#include <string>
#include <variant>

namespace RequestAnswers
{
	struct AnswerGetServerName
	{
		std::string serverName;
	};

	using RequestAnswer = std::variant<AnswerGetServerName>;

	std::optional<std::string> sendRequestAnswer(int socket, RequestAnswer&& requestAnswer);
} // namespace RequestAnswers
