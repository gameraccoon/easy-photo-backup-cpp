// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "common_shared/debug/assert.h"

namespace Debug::Assert
{
	AssertHandlerFn gGlobalAssertHandler = [] {
		// ToDo: we need to add a debugger trap here
	};
	AssertHandlerFn gGlobalFatalAssertHandler = [] { std::terminate(); };
	bool gGlobalAllowAssertLogs = true;
} // namespace Debug::Assert
