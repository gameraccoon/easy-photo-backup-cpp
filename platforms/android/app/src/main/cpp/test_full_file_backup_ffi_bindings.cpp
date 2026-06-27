#include <format>
#include <string>

#include <jni.h>

#include "client_shared/test_full_file_backup.h"

class TestFullFileBackupNative
{
public:
	TestFullFileBackupNative(const std::filesystem::path& localStorageDirectory)
		: mTestState(localStorageDirectory)
	{
	}

	void startDiscovery()
	{
		mTestState.startDiscovery();
	}

	std::vector<TestServerInfo> getDiscoveryResults()
	{
		return mTestState.getDiscoveryResults();
	}

	void stopDiscovery()
	{
		mTestState.stopDiscovery();
	}

	static std::optional<std::string> requestServerName(const Network::NetworkAddress& address)
	{
		return TestFullFileBackup::requestServerName(address);
	}

	// ToDo: this is the bad and dangerous part, should be removed altogether before the app can be used for real
	std::optional<std::string> pairAndApproveServer(const TestServerInfo& serverInfo)
	{
		return mTestState.pairAndApproveServer(serverInfo);
	}

	std::optional<std::string> sendFiles(const TestServerInfo& serverInfo, const std::string& folderPath, const std::string& commonRoot)
	{
		return mTestState.sendFiles(serverInfo, folderPath, commonRoot);
	}

	std::optional<std::string> removeServer(const std::array<std::byte, 16>& serverId)
	{
		return mTestState.removeServer(serverId);
	}

	bool isServerPaired(const std::array<std::byte, 16>& serverId) const
	{
		return mTestState.isServerPaired(serverId);
	}

private:
	TestFullFileBackup mTestState;
};

class TestServerInfoNative
{
public:
	TestServerInfoNative(TestServerInfo inServerInfo)
		: serverInfo(std::move(inServerInfo))
	{}

	TestServerInfo serverInfo;
};

extern "C" JNIEXPORT jlong JNICALL
Java_com_unnamed_easyphotobackup_TestFullFileBackup_create(
	JNIEnv* env,
	jobject /*this*/,
	jstring localStoragePathJStr
)
{
	const char* localStoragePathCStr = env->GetStringUTFChars(localStoragePathJStr, nullptr);
	const std::filesystem::path localStoragePath(localStoragePathCStr);
	env->ReleaseStringUTFChars(localStoragePathJStr, localStoragePathCStr);

	auto* obj = new TestFullFileBackupNative(localStoragePath);
	return reinterpret_cast<jlong>(obj);
}

extern "C" JNIEXPORT void JNICALL
Java_com_unnamed_easyphotobackup_TestFullFileBackup_destroy(
	JNIEnv* env,
	jobject /*this*/,
	jlong handle
)
{
	auto* obj = reinterpret_cast<TestFullFileBackupNative*>(handle);
	delete obj;
}

extern "C" JNIEXPORT void JNICALL
Java_com_unnamed_easyphotobackup_TestServerInfo_destroy(
	JNIEnv* env,
	jobject /*this*/,
	jlong handle
)
{
	auto* obj = reinterpret_cast<TestServerInfoNative*>(handle);
	delete obj;
}

extern "C" JNIEXPORT void JNICALL
Java_com_unnamed_easyphotobackup_TestFullFileBackup_startDiscoveryNative(
	JNIEnv* env,
	jobject /*this*/,
	jlong handle
)
{
	auto* obj = reinterpret_cast<TestFullFileBackupNative*>(handle);
	obj->startDiscovery();
}

extern "C" JNIEXPORT jlongArray JNICALL
Java_com_unnamed_easyphotobackup_TestFullFileBackup_getDiscoveryResultsNative(
	JNIEnv* env,
	jobject /*this*/,
	jlong handle
)
{
	auto* obj = reinterpret_cast<TestFullFileBackupNative*>(handle);
	auto discoveryResults = obj->getDiscoveryResults();

	jlongArray result = env->NewLongArray(static_cast<jsize>(discoveryResults.size()));

	std::vector<jlong> handles;
	handles.reserve(discoveryResults.size());

	for (auto& result : discoveryResults)
	{
		handles.push_back(reinterpret_cast<jlong>(new TestServerInfoNative(std::move(result))));
	}

	env->SetLongArrayRegion(
		result,
		0,
		static_cast<jsize>(handles.size()),
		handles.data()
	);

	return result;
}

extern "C" JNIEXPORT void JNICALL
Java_com_unnamed_easyphotobackup_TestFullFileBackup_stopDiscoveryNative(
	JNIEnv* env,
	jobject /*this*/,
	jlong handle
)
{
	auto* obj = reinterpret_cast<TestFullFileBackupNative*>(handle);
	obj->stopDiscovery();
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_unnamed_easyphotobackup_TestFullFileBackup_requestServerNameNative(
	JNIEnv* env,
	jobject /*this*/,
	jlong handle,
	jlong serverInfoHandle
)
{
	// auto* obj = reinterpret_cast<TestFullFileBackupNative*>(handle);
	auto* info = reinterpret_cast<TestServerInfoNative*>(serverInfoHandle);

	auto serverName = TestFullFileBackupNative::requestServerName(info->serverInfo.address);

	if (!serverName.has_value())
	{
		return nullptr;
	}

	return env->NewStringUTF(serverName->c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_unnamed_easyphotobackup_TestFullFileBackup_pairAndApproveServerNative(
	JNIEnv* env,
	jobject /*this*/,
	jlong handle,
	jlong serverInfoHandle
)
{
	auto* obj = reinterpret_cast<TestFullFileBackupNative*>(handle);
	auto* info = reinterpret_cast<TestServerInfoNative*>(serverInfoHandle);

	auto result = obj->pairAndApproveServer(info->serverInfo);

	if (result.has_value())
	{
		return env->NewStringUTF(result->c_str());
	}

	return nullptr;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_unnamed_easyphotobackup_TestFullFileBackup_sendFilesNative(
	JNIEnv* env,
	jobject /*this*/,
	jlong handle,
	jlong serverInfoHandle,
	jstring folderPathJStr,
	jstring commonRootPathJStr
)
{
	auto* obj = reinterpret_cast<TestFullFileBackupNative*>(handle);
	auto* info = reinterpret_cast<TestServerInfoNative*>(serverInfoHandle);

	const char* folderPathChar = env->GetStringUTFChars(folderPathJStr, nullptr);
	std::string folderPath(folderPathChar);
	env->ReleaseStringUTFChars(folderPathJStr, folderPathChar);

	const char* commonRootPathChar = env->GetStringUTFChars(commonRootPathJStr, nullptr);
	std::string commonRootPath(commonRootPathChar);
	env->ReleaseStringUTFChars(commonRootPathJStr, commonRootPathChar);

	auto result = obj->sendFiles(info->serverInfo, folderPath, commonRootPath);

	if (result.has_value())
	{
		return env->NewStringUTF(result->c_str());
	}

	return nullptr;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_unnamed_easyphotobackup_TestFullFileBackup_removeServerNative(
	JNIEnv* env,
	jobject /*this*/,
	jlong handle,
	jlong serverInfoHandle
)
{
	auto* obj = reinterpret_cast<TestFullFileBackupNative*>(handle);
	auto* info = reinterpret_cast<TestServerInfoNative*>(serverInfoHandle);

	auto result = obj->removeServer(info->serverInfo.serverId);

	if (result.has_value())
	{
		return env->NewStringUTF(result->c_str());
	}

	return nullptr;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_unnamed_easyphotobackup_TestFullFileBackup_isServerPaired(
	JNIEnv* env,
	jobject /*this*/,
	jlong handle,
	jlong serverInfoHandle
)
{
	auto* obj = reinterpret_cast<TestFullFileBackupNative*>(handle);
	auto* info = reinterpret_cast<TestServerInfoNative*>(serverInfoHandle);

	return obj->isServerPaired(info->serverInfo.serverId);
}
