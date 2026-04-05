// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <gtest/gtest.h>

#include "common_shared/debug/assert.h"

namespace AssertHelper
{
	inline void disableAsserts() noexcept
	{
		Debug::Assert::gGlobalAllowAssertLogs = false;
		Debug::Assert::gGlobalAssertHandler = [] {};
		// we don't disable fatal assert handler, since tha one should only signal about serious logical erros
		// which should not depend on the input data
	}

	inline void enableAsserts() noexcept
	{
		Debug::Assert::gGlobalAllowAssertLogs = true;
		Debug::Assert::gGlobalAssertHandler = [] { GTEST_FAIL(); };
		Debug::Assert::gGlobalFatalAssertHandler = [] { GTEST_FATAL_FAILURE_("Fatal assert called"); };
	}

	class ScopedAssertDisabler
	{
	public:
		ScopedAssertDisabler() noexcept
		{
			if (gScopeCounter == 0)
			{
				disableAsserts();
			}
			++gScopeCounter;
		}

		~ScopedAssertDisabler() noexcept
		{
			--gScopeCounter;
			if (gScopeCounter == 0)
			{
				enableAsserts();
			}
		}

		// rule of 5
		ScopedAssertDisabler(const ScopedAssertDisabler&) noexcept = delete;
		ScopedAssertDisabler& operator=(const ScopedAssertDisabler&) noexcept = delete;
		ScopedAssertDisabler(ScopedAssertDisabler&&) noexcept = delete;
		ScopedAssertDisabler& operator=(ScopedAssertDisabler&&) noexcept = delete;

	private:
		static inline int gScopeCounter = 0;
	};
} // namespace AssertHelper
