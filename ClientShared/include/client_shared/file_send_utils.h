// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <filesystem>

#include "common_shared/cryptography/noise/cipher_types.h"

namespace FileSendUtils
{
	void sendDirectory(const std::filesystem::path& directoryPath, int socket, Noise::CipherStateSending& sendingCipherstate, Noise::CipherStateReceiving& receivingCipherState) noexcept;
}
