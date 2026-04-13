// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <string_view>

#include "common_shared/network/utils.h"

#include "client_shared/client_storage.h"

namespace Requests
{
	bool sendAndProcessPairingInteractiveRequest(Network::RawSocket socket, ClientStorage& storage, std::string_view serverName);
}
