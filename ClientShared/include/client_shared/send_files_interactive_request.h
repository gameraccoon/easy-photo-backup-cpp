// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include "common_shared/network/utils.h"

#include "client_shared/request_answers.h"

class ClientStorage;

namespace Requests
{
	RequestAnswers::RequestAnswer sendAndProcessSendFilesInteractiveRequest(Network::RawSocket socket, ClientStorage& storage, const std::string& serverName) noexcept;
}
