// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "common_shared/cryptography/utils/erasable_data.h"

namespace Cryptography
{
	using StaticAssertTestByteSequence = ByteSequence<Tag::TempInternalBuffer, 60>;
	// these are important for some of the static asserts to work
	// (some require using sizeof when passed by reference)
	static_assert(sizeof(StaticAssertTestByteSequence::raw) == 60);
	static_assert(sizeof(StaticAssertTestByteSequence) == 60);
} // namespace Cryptography
