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
		// make sure GetProtocolVersion does not change the ID or data
		// as it should remain the same across all versions in order for it to work
		GetProtocolVersion = 0,
		GetServerName = 1,
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
	};

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
} // namespace Protocol
