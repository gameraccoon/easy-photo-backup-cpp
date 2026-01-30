// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "common_shared/nsd/utils.h"

namespace NsdServer
{
	using ListenResult = std::optional<std::string>;

	ListenResult listen(
		const char* interfaceAddressStr,
		NsdUtils::AddressType addressType,
		uint16_t port,
		const char* serviceIdentifier,
		uint16_t advertizedPort,
		const std::vector<std::byte>& extraData
	);
}
