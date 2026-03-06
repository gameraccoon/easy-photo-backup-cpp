// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include <span>
#include <string>
#include <variant>

namespace Requests
{
	struct RequestReadError
	{
		std::string err;
	};

	struct GetServerName
	{
	};

	using RequestVariant = std::variant<RequestReadError, GetServerName>;

	RequestVariant parseRequest(std::byte requestId, const std::span<std::byte>& requestData);
} // namespace Requests
