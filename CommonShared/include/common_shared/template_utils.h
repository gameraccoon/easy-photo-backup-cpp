// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).
#pragma once

template<class... Ts>
struct VisitLambda : Ts...
{
	using Ts::operator()...;
};
