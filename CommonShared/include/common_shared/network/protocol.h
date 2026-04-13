// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <array>
#include <cstdint>
#include <string>

namespace Protocol
{
	// increase the version every time the protocol changes
	constexpr uint16_t NetworkProtocolVersion = 0;

	enum class RequestId : uint8_t
	{
		// make sure GetProtocolVersion does not change the ID or data
		// as it should remain the same across all versions in order for it to work
		GetProtocolVersion = 0,
		GetServerName = 1,
		Pair = 2,
	};

	enum class RequestAnswerId : uint8_t
	{
		// make sure UnsupportedProtocolVersion does not change the ID or data
		// as it should remain the same across all versions in order for it to work
		UnsupportedProtocolVersion = 0,
		// make sure GetProtocolVersion does not change the ID or data
		// as it should remain the same across all versions in order for it to work
		GetProtocolVersion = 1,
		GetServerName = 2,
		Pair = 3,
	};

	constexpr size_t MaxRequestSize = 1024;
	constexpr size_t MaxRequestAnswerSize = 1024;

	constexpr uint16_t MaxServerNameSize = 32;

	namespace Requests
	{
		// make sure GetProtocolVersion does not change the ID or data
		// as it should remain the same across all versions in order for it to work
		struct GetProtocolVersion
		{
		};

		struct GetServerName
		{
		};
	} // namespace Requests

	namespace RequestAnswers
	{
		// make sure UnsupportedProtocolVersion does not change the ID or data
		// as it should remain the same across all versions in order for it to work
		struct UnsupportedProtocolVersion
		{
			uint16_t firstSupportedProtocolVersion = 0;
		};

		// make sure GetProtocolVersion does not change the ID or data
		// as it should remain the same across all versions in order for it to work
		struct GetProtocolVersion
		{
			uint16_t protocolVersion = 0;
		};

		struct GetServerName
		{
			std::string serverName;
		};
	} // namespace RequestAnswers

	// interactive requests have their own internal implementation details
	// changing the interaction details requires changing NetworkProtocolVersion
	constexpr std::array<std::byte, 1> InteractiveRequests{
		static_cast<std::byte>(RequestId::Pair),
	};
} // namespace Protocol
