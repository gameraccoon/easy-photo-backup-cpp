// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <cstdint>

namespace Protocol
{
	// increase the version every time the protocol changes
	constexpr uint16_t NetworkProtocolVersion = 0;

	enum class Request : uint8_t
	{
		GetServerName = 0,
	};

	enum class RequestAnswer : uint8_t
	{
		AnswerGetServerName = 0,
	};

	constexpr uint16_t MaxServerNameSize = 32;
}
