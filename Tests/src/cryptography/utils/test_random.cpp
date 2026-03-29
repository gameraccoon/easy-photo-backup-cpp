// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include <array>

#include <gtest/gtest.h>

#include "common_shared/cryptography/utils/random.h"

TEST(CryptographyRandom, random_producesNonZeroArray)
{
	std::array<uint8_t, 50> data = {};

	Cryptography::fillWithRandomBytes(data);

	bool onlyZeroes = true;
	for (const uint8_t v : data)
	{
		if (v != 0) { onlyZeroes = false; }
	}

	// this is of couse has a chance to fail, but a false positive once a decade still
	// worth it testing that the app is not completely broken
	EXPECT_FALSE(onlyZeroes);
}
