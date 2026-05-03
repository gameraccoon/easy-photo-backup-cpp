// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include <gtest/gtest.h>

#include "common_shared/files/file_utils.h"

TEST(FileUtils, isFileAcceptable_test)
{
	EXPECT_TRUE(Files::isFilePathAcceptable("file.txt"));
	EXPECT_TRUE(Files::isFilePathAcceptable("no_ext"));
	EXPECT_TRUE(Files::isFilePathAcceptable("file.jpg"));
	EXPECT_TRUE(Files::isFilePathAcceptable("file.jpeg"));
	EXPECT_TRUE(Files::isFilePathAcceptable("file.exe"));
	EXPECT_TRUE(Files::isFilePathAcceptable("file.two.extensions"));
	EXPECT_TRUE(Files::isFilePathAcceptable("file name with spaces"));
	EXPECT_TRUE(Files::isFilePathAcceptable("file..name..with..dots"));
	EXPECT_TRUE(Files::isFilePathAcceptable("dir/file.txt"));
	EXPECT_TRUE(Files::isFilePathAcceptable("folder\\file.txt"));
	EXPECT_TRUE(Files::isFilePathAcceptable("dir//file.txt"));
	EXPECT_TRUE(Files::isFilePathAcceptable("long/long/path/to/a/file/consisting/of/many/subdirectories.txt"));
	EXPECT_TRUE(Files::isFilePathAcceptable("path/with spaces.txt"));
	EXPECT_FALSE(Files::isFilePathAcceptable(""));
	EXPECT_FALSE(Files::isFilePathAcceptable("../file_escaping_root.txt"));
	EXPECT_FALSE(Files::isFilePathAcceptable("./file_with_extra_spec.txt"));
	EXPECT_FALSE(Files::isFilePathAcceptable("./../file.txt"));
	EXPECT_FALSE(Files::isFilePathAcceptable("test/../file.txt"));
	EXPECT_FALSE(Files::isFilePathAcceptable("test/./file.txt"));
	EXPECT_FALSE(Files::isFilePathAcceptable("/global//path.txt"));
	EXPECT_FALSE(Files::isFilePathAcceptable("/file /with_root_in_the_middle.txt"));

#if defined(_WIN32) || defined(_WIN64)
	// should be rejected on Windows, but may be valid if sending between linux machines
	EXPECT_FALSE(Files::isFilePathAcceptable("D:/another/global/path.txt"));
	EXPECT_FALSE(Files::isFilePathAcceptable("C:"));
#endif
}
