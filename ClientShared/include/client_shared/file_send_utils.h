// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#ifdef WITH_TESTS
#include <fstream>
#include <functional>
#include <optional>
#endif

#include <filesystem>

#include "common_shared/cryptography/noise/cipher_types.h"
#include "common_shared/network/utils.h"

namespace FileSendUtils
{
#ifdef WITH_TESTS
	struct Mocks
	{
		std::function<void(std::vector<std::filesystem::path>&)> getAllFiles;
		std::function<void(std::ifstream&, const std::filesystem::path&)> openFile;
		std::function<size_t(std::ifstream& file)> getFileLength;
		std::function<bool(std::ifstream&)> isFileOpen;
		std::function<void(std::ifstream&, std::span<std::byte>)> readFileStreamIntoSpan;
		std::function<std::optional<std::string>(Network::RawSocket, std::span<std::byte>, size_t, Noise::CipherStateSending&)> sendBuffer;
	};
#else
	struct Mocks
	{
	};
#endif

	void sendDirectory(const std::filesystem::path& directoryPath, Network::RawSocket socket, Noise::CipherStateSending& sendingCipherstate, Noise::CipherStateReceiving& receivingCipherState, Mocks mocks = {}) noexcept;
}
