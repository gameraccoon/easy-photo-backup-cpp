// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "server_shared/requests.h"

#include <format>

#include "common_shared/debug/assert.h"

namespace Requests
{
	RequestVariant parseRequest(std::byte requestId, const std::span<std::byte>& /*requestData*/)
	{
		switch (static_cast<char>(requestId))
		{
		case static_cast<char>(Protocol::RequestId::GetServerName):
			return GetServerName{};
		default:
			reportDebugError("Unknown request ID {}", static_cast<int>(requestId));
			return RequestReadError{ std::format("Unknown request ID {}", static_cast<int>(requestId)) };
		}
	}
} // namespace Requests
