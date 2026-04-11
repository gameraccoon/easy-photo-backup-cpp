// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include "common_shared/network/protocol.h"
#include "common_shared/network/utils.h"

namespace Requests
{
	void processPairingInteractiveRequest(std::array<std::byte, Protocol::MaxRequestSize>& buffer, size_t readBytes, const Network::RawSocket socket);
}
