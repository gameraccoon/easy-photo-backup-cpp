// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <future>
#include <optional>
#include <string>

#include "common_shared/network/utils.h"

namespace TcpServer
{
	std::optional<std::string> runServer(const char* interfaceAddressStr, Network::AddressType addressType, std::promise<uint16_t>& portPromise);
}
