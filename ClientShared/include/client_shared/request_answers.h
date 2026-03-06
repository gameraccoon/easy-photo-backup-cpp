// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <string>
#include <variant>

namespace RequestAnswers
{
	struct Error
	{
		std::string errorMessage;
	};

	struct LogicalError
	{
		std::string errorMessage;
	};

	// the request expected no asnwer
	struct ExpectedNoAnswer
	{
	};

	struct AnswerGetServerName
	{
		std::string name;
	};

	using RequestAnswer = std::variant<Error, LogicalError, ExpectedNoAnswer, AnswerGetServerName>;
} // namespace RequestAnswers
