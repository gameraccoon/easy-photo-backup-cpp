// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace NsdServer
{
	enum class AddressType
	{
		IpV4,
		IpV6,
	};

	using ListenResult = std::optional<std::string>;

	ListenResult listen(
		const char* interfaceAddressStr,
		AddressType addressType,
		uint16_t port,
		const char* serviceId,
		uint16_t advertizedPort,
		const std::vector<std::byte>& extraData
	);
}
