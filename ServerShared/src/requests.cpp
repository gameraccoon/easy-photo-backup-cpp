// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "server_shared/requests.h"

#include <format>

#include "common_shared/debug/assert.h"

namespace Requests
{
	RequestVariant parseRequest(std::byte requestId, const std::span<const std::byte> requestData)
	{
		switch (static_cast<char>(requestId))
		{
		case static_cast<char>(Protocol::RequestId::GetServerName):
			return GetServerName{};
		case static_cast<char>(Protocol::RequestId::Pair):
			return Pair{
				.firstMessage = std::vector<std::byte>(requestData.begin(), requestData.end()),
			};
		case static_cast<char>(Protocol::RequestId::SendFiles): {
			if (requestData.size() < sizeof(Protocol::Requests::SendFiles::connectionId))
			{
				return RequestReadError{ std::format("SendFiles request had shorter data than expected {}", requestData.size()) };
			}

			Cryptography::HashResult clientIdentifier;
			const size_t firstMessageStart = clientIdentifier.size();
			std::copy(requestData.begin(), requestData.begin() + clientIdentifier.size(), clientIdentifier.raw.begin());

			return SendFiles{
				.connectionId = std::move(clientIdentifier),
				.firstMessage = std::vector<std::byte>(requestData.begin() + firstMessageStart, requestData.end()),
			};
		}
		default:
			reportDebugError("Unknown request ID {}", static_cast<int>(requestId));
			return RequestReadError{ std::format("Unknown request ID {}", static_cast<int>(requestId)) };
		}
	}
} // namespace Requests
