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

	[[nodiscard]] std::vector<TestServerInfo> getDiscoveryResults()
	{
		return mTestState.getDiscoveryResults();
	}

	void stopDiscovery()
	{
		mTestState.stopDiscovery();
	}

	[[nodiscard]] static std::optional<std::string> requestServerName(const Network::NetworkAddress& address)
	{
		return TestFullFileBackup::requestServerName(address);
	}

	[[nodiscard]] std::variant<std::string, PendingServerBinding> exchangePairInformationWithServer(const TestServerInfo& serverInfo)
	{
		return mTestState.exchangePairInformationWithServer(serverInfo);
	}

	[[nodiscard]] std::optional<std::string> approveServer(const TestServerInfo& serverInfo, const PendingServerBinding& serverBindingInfo)
	{
		return mTestState.approveServer(serverInfo, serverBindingInfo);
	}

	[[nodiscard]] std::optional<std::string> sendFiles(const TestServerInfo& serverInfo, const std::string& folderPath, const std::string& commonRoot)
	{
		return mTestState.sendFiles(serverInfo, folderPath, commonRoot);
	}

	[[nodiscard]] std::optional<std::string> removeServer(const std::array<std::byte, 16>& serverId)
	{
		return mTestState.removeServer(serverId);
	}

	[[nodiscard]] bool isServerPaired(const std::array<std::byte, 16>& serverId) const
	{
		return mTestState.isServerPaired(serverId);
	}

private:
	TestFullFileBackup mTestState;
};

class TestServerInfoNative
{
public:
	TestServerInfoNative(TestServerInfo&& inServerInfo) noexcept
		: serverInfo(std::move(inServerInfo))
	{}

	TestServerInfo serverInfo;
};

class PendingServerBindingNative
{
public:
	PendingServerBindingNative(PendingServerBinding&& inServerBinding)
		: serverBinding(std::move(inServerBinding))
	{}

	[[nodiscard]] std::string generateShortAuthentificationString() const noexcept
	{
		return serverBinding.generateShortAuthentificationString();
	}

	PendingServerBinding serverBinding;
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

	TestFullFileBackupNative* obj = new TestFullFileBackupNative(localStoragePath);
	return reinterpret_cast<jlong>(obj);
}

extern "C" JNIEXPORT void JNICALL
Java_com_unnamed_easyphotobackup_TestFullFileBackup_destroy(
	JNIEnv* env,
	jobject /*this*/,
	jlong handle
)
{
	TestFullFileBackupNative* obj = reinterpret_cast<TestFullFileBackupNative*>(handle);
	delete obj;
}

extern "C" JNIEXPORT void JNICALL
Java_com_unnamed_easyphotobackup_TestFullFileBackup_startDiscoveryNative(
	JNIEnv* env,
	jobject /*this*/,
	jlong handle
)
{
	TestFullFileBackupNative* obj = reinterpret_cast<TestFullFileBackupNative*>(handle);
	obj->startDiscovery();
}

extern "C" JNIEXPORT jlongArray JNICALL
Java_com_unnamed_easyphotobackup_TestFullFileBackup_getDiscoveryResultsNative(
	JNIEnv* env,
	jobject /*this*/,
	jlong handle
)
{
	TestFullFileBackupNative* obj = reinterpret_cast<TestFullFileBackupNative*>(handle);
	std::vector<TestServerInfo> discoveryResults = obj->getDiscoveryResults();

	jlongArray result = env->NewLongArray(static_cast<jsize>(discoveryResults.size()));

	std::vector<jlong> handles;
	handles.reserve(discoveryResults.size());

	for (TestServerInfo& discoveryResult : discoveryResults)
	{
		handles.push_back(reinterpret_cast<jlong>(new TestServerInfoNative(std::move(discoveryResult))));
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
	TestFullFileBackupNative* obj = reinterpret_cast<TestFullFileBackupNative*>(handle);
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
	TestServerInfoNative* info = reinterpret_cast<TestServerInfoNative*>(serverInfoHandle);

	std::optional<std::string> serverName = TestFullFileBackupNative::requestServerName(info->serverInfo.address);

	if (!serverName.has_value())
	{
		return nullptr;
	}

	return env->NewStringUTF(serverName->c_str());
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_unnamed_easyphotobackup_TestFullFileBackup_exchangePairingInformationWithServer(
	JNIEnv* env,
	jobject /*this*/,
	jlong handle,
	jlong serverInfoHandle
)
{
	TestFullFileBackupNative* obj = reinterpret_cast<TestFullFileBackupNative*>(handle);
	TestServerInfoNative* info = reinterpret_cast<TestServerInfoNative*>(serverInfoHandle);

	std::variant<std::string, PendingServerBinding> result = obj->exchangePairInformationWithServer(info->serverInfo);

	if (std::holds_alternative<PendingServerBinding>(result))
	{
		return reinterpret_cast<jlong>(new PendingServerBindingNative(std::move(std::get<PendingServerBinding>(result))));
	}

	return 0;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_unnamed_easyphotobackup_TestFullFileBackup_approveServer(
	JNIEnv* env,
	jobject /*this*/,
	jlong handle,
	jlong serverInfoHandle,
	jlong pendingServerBindingHandle
)
{
	TestFullFileBackupNative* obj = reinterpret_cast<TestFullFileBackupNative*>(handle);
	TestServerInfoNative* info = reinterpret_cast<TestServerInfoNative*>(serverInfoHandle);
	PendingServerBindingNative* pendingServerBindingNative = reinterpret_cast<PendingServerBindingNative*>(pendingServerBindingHandle);

	std::optional<std::string> result = obj->approveServer(info->serverInfo, pendingServerBindingNative->serverBinding);

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
	TestFullFileBackupNative* obj = reinterpret_cast<TestFullFileBackupNative*>(handle);
	TestServerInfoNative* info = reinterpret_cast<TestServerInfoNative*>(serverInfoHandle);

	const char* folderPathChar = env->GetStringUTFChars(folderPathJStr, nullptr);
	std::string folderPath(folderPathChar);
	env->ReleaseStringUTFChars(folderPathJStr, folderPathChar);

	const char* commonRootPathChar = env->GetStringUTFChars(commonRootPathJStr, nullptr);
	std::string commonRootPath(commonRootPathChar);
	env->ReleaseStringUTFChars(commonRootPathJStr, commonRootPathChar);

	std::optional<std::string> result = obj->sendFiles(info->serverInfo, folderPath, commonRootPath);

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
	TestFullFileBackupNative* obj = reinterpret_cast<TestFullFileBackupNative*>(handle);
	TestServerInfoNative* info = reinterpret_cast<TestServerInfoNative*>(serverInfoHandle);

	std::optional<std::string> result = obj->removeServer(info->serverInfo.serverId);

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
	TestFullFileBackupNative* obj = reinterpret_cast<TestFullFileBackupNative*>(handle);
	TestServerInfoNative* info = reinterpret_cast<TestServerInfoNative*>(serverInfoHandle);

	return obj->isServerPaired(info->serverInfo.serverId);
}

extern "C" JNIEXPORT void JNICALL
Java_com_unnamed_easyphotobackup_TestServerInfo_destroy(
	JNIEnv* env,
	jobject /*this*/,
	jlong handle
)
{
	TestServerInfoNative* obj = reinterpret_cast<TestServerInfoNative*>(handle);
	delete obj;
}

extern "C" JNIEXPORT void JNICALL
Java_com_unnamed_easyphotobackup_PendingServerBinding_destroy(
	JNIEnv* env,
	jobject /*this*/,
	jlong handle
)
{
	PendingServerBindingNative* obj = reinterpret_cast<PendingServerBindingNative*>(handle);
	delete obj;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_unnamed_easyphotobackup_PendingServerBinding_generateShortAuthentificationString(
	JNIEnv* env,
	jobject /*this*/,
	jlong handle
)
{
	PendingServerBindingNative* obj = reinterpret_cast<PendingServerBindingNative*>(handle);
	std::string sas = obj->generateShortAuthentificationString();
	return env->NewStringUTF(sas.c_str());
}
