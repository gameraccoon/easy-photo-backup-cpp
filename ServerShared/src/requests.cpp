// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "server_shared/requests.h"

#include <format>

#include "common_shared/network/protocol.h"

namespace Requests
{
	RequestVariant parseRequest(std::byte requestId, const std::span<std::byte>& requestData)
	{
		switch (requestId)
		{
		case static_cast<std::byte>(Protocol::Request::GetServerName):
			return GetServerName{};
		default:
			return RequestReadError{ std::format("Unknown request ID {}", static_cast<int>(requestId)) };
		}
	}
} // namespace Requests
