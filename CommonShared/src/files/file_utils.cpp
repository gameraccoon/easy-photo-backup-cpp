// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "common_shared/files/file_utils.h"

namespace Files
{
	bool isFilePathAcceptable(const std::filesystem::path& path) noexcept
	{
		if (path.empty())
		{
			return false;
		}

		if (path.is_absolute())
		{
			return false;
		}

		// make sure the path doesn't contain /./ and /../ parts in the middle
		if (path.lexically_normal() != path)
		{
			return false;
		}

		// check that the path doesn't start with ..
		std::filesystem::path parent = path;
		while (parent.has_parent_path())
		{
			parent = parent.parent_path();
		}
		return parent != "..";
	}
} // namespace Files
