// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <cstdint>
#include <string>

namespace Protocol
{
	// increase the version every time the protocol changes
	constexpr uint16_t NetworkProtocolVersion = 0;

	enum class RequestId : uint8_t
	{
		GetServerName = 0,
	};

	enum class RequestAnswerId : uint8_t
	{
		AnswerGetServerName = 0,
	};

	constexpr uint16_t MaxServerNameSize = 32;

	namespace Requests
	{
		struct GetServerName
		{
		};
	} // namespace Requests

	namespace RequestAnswers
	{
		struct GetServerName
		{
			std::string serverName;
		};
	} // namespace RequestAnswers
} // namespace Protocol
