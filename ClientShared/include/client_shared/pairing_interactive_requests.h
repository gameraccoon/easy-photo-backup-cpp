// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include "common_shared/network/utils.h"

#include "client_shared/request_answers.h"

namespace Requests
{
	RequestAnswers::RequestAnswer sendAndProcessPairingInteractiveRequest(Network::RawSocket socket);
}
