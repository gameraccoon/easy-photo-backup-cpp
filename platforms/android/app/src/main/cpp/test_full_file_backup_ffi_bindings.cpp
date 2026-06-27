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

	std::vector<Network::NetworkAddress> getDiscoveryResults()
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
	std::optional<std::string> pairAndApproveServer(const Network::NetworkAddress& address, const std::string& serverName)
	{
		return mTestState.pairAndApproveServer(address, serverName);
	}

	std::optional<std::string> sendFiles(const Network::NetworkAddress& address, const std::string& serverName, const std::string& folderPath)
	{
		return mTestState.sendFiles(address, serverName, folderPath);
	}

	std::optional<std::string> removeServer(const std::string& serverName)
	{
		return mTestState.removeServer(serverName);
	}

	bool isServerPaired(const std::string& serverName) const
	{
		return mTestState.isServerPaired(serverName);
	}

private:
	TestFullFileBackup mTestState;
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
Java_com_unnamed_easyphotobackup_TestFullFileBackup_startDiscoveryNative(
	JNIEnv* env,
	jobject /*this*/,
	jlong handle
)
{
	auto* obj = reinterpret_cast<TestFullFileBackupNative*>(handle);
	obj->startDiscovery();
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_unnamed_easyphotobackup_TestFullFileBackup_getDiscoveryResultsNative(
	JNIEnv* env,
	jobject /*this*/,
	jlong handle
)
{
	auto* obj = reinterpret_cast<TestFullFileBackupNative*>(handle);
	std::vector<Network::NetworkAddress> discoveryResults = obj->getDiscoveryResults();

	jclass stringClass = env->FindClass("java/lang/String");

	jobjectArray result = env->NewObjectArray(
		static_cast<int>(discoveryResults.size()),
		stringClass,
		nullptr
	);

	for (size_t i = 0; i < discoveryResults.size(); ++i)
	{
		std::string addressString = discoveryResults[i].toString();
		jstring str = env->NewStringUTF(addressString.c_str());
		env->SetObjectArrayElement(result, static_cast<int>(i), str);
		env->DeleteLocalRef(str);
	}

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
	jstring addressJStr
)
{
	//	auto* obj = reinterpret_cast<TestFullFileBackupNative*>(handle);

	const char* addressChar = env->GetStringUTFChars(addressJStr, nullptr);
	const std::optional<Network::NetworkAddress> address = Network::NetworkAddress::fromString(addressChar);
	env->ReleaseStringUTFChars(addressJStr, addressChar);

	if (!address.has_value())
	{
		return nullptr;
	}

	std::optional<std::string> serverName = TestFullFileBackupNative::requestServerName(*address);

	if (serverName.has_value())
	{
		return env->NewStringUTF(serverName->c_str());
	}

	return nullptr;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_unnamed_easyphotobackup_TestFullFileBackup_pairAndApproveServerNative(
	JNIEnv* env,
	jobject /*this*/,
	jlong handle,
	jstring addressJStr,
	jstring serverNameJStr
)
{
	const char* addressChar = env->GetStringUTFChars(addressJStr, nullptr);
	std::optional<Network::NetworkAddress> address = Network::NetworkAddress::fromString(addressChar);
	env->ReleaseStringUTFChars(addressJStr, addressChar);

	if (!address.has_value())
	{
		return env->NewStringUTF("Address could not be parsed");
	}

	const char* serverNameChar = env->GetStringUTFChars(serverNameJStr, nullptr);
	const std::string serverName(serverNameChar);
	env->ReleaseStringUTFChars(serverNameJStr, serverNameChar);

	auto* obj = reinterpret_cast<TestFullFileBackupNative*>(handle);
	std::optional<std::string> result = obj->pairAndApproveServer(*address, serverName);
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
	jstring addressJStr,
	jstring serverNameJStr,
	jstring folderPathJStr
)
{
	const char* addressChar = env->GetStringUTFChars(addressJStr, nullptr);
	std::optional<Network::NetworkAddress> address = Network::NetworkAddress::fromString(addressChar);
	env->ReleaseStringUTFChars(addressJStr, addressChar);

	if (!address.has_value())
	{
		return env->NewStringUTF("Address could not be parsed");
	}

	const char* serverNameChar = env->GetStringUTFChars(serverNameJStr, nullptr);
	const std::string serverName(serverNameChar);
	env->ReleaseStringUTFChars(serverNameJStr, serverNameChar);

	const char* folderPathChar = env->GetStringUTFChars(folderPathJStr, nullptr);
	const std::string folderPath(folderPathChar);
	env->ReleaseStringUTFChars(folderPathJStr, folderPathChar);

	auto* obj = reinterpret_cast<TestFullFileBackupNative*>(handle);
	std::optional<std::string> result = obj->sendFiles(*address, serverName, folderPath);
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
	jstring serverNameJStr
)
{
	const char* serverNameChar = env->GetStringUTFChars(serverNameJStr, nullptr);
	const std::string serverName(serverNameChar);
	env->ReleaseStringUTFChars(serverNameJStr, serverNameChar);

	auto* obj = reinterpret_cast<TestFullFileBackupNative*>(handle);
	std::optional<std::string> result = obj->removeServer(serverName);
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
	jstring serverNameJStr
)
{
	const char* serverNameChar = env->GetStringUTFChars(serverNameJStr, nullptr);
	const std::string serverName(serverNameChar);
	env->ReleaseStringUTFChars(serverNameJStr, serverNameChar);

	auto* obj = reinterpret_cast<TestFullFileBackupNative*>(handle);
	return obj->isServerPaired(serverName);
}
