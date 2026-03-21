// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "common_shared/cryptography/random.h"

#if defined(_WIN32) || defined(_WIN64)
// clang-format off
// order matters
#include <Windows.h>
#include <bcrypt.h>
// clang-format on
#elif defined(__linux__) && !defined(__ANDROID__)
#include <sys/random.h>
#elif defined(__FreeBSD__)
#include <bsd/stdlib.h>
#else
#include <cstdlib>
#endif

namespace Cryptography
{
	void fillWithRandomBytes(std::span<uint8_t> outNumber)
	{
		// see https://monocypher.org/manual/#Random_number_generation
#if defined(_WIN32) || defined(_WIN64)
		BCryptGenRandom(nullptr, outNumber.data(), static_cast<ULONG>(outNumber.size()), 0);
#elif defined(__linux__) && !defined(__ANDROID__)
		getrandom(outNumber.data(), outNumber.size(), 0);
#else
		arc4random_buf(outNumber.data(), outNumber.size());
#endif
	}
} // namespace Cryptography
