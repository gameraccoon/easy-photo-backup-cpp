#include <format>
#include <string>

#include <jni.h>

#include "client_shared/test_full_file_backup.h"

class TestFullFileBackupNative
{
public:
	void startDiscovery()
	{
		testState.startDiscovery();
	}

	std::vector<Network::NetworkAddress> getDiscoveryResults()
	{
		return testState.getDiscoveryResults();
	}

	void stopDiscovery()
	{
		testState.stopDiscovery();
	}

	static std::optional<std::string> requestServerName(const Network::NetworkAddress& address)
	{
		return TestFullFileBackup::requestServerName(address);
	}

	// ToDo: this is the bad and dangerous part, should be removed altogether before the app can be used for real
	void pairAndApproveServer(const Network::NetworkAddress& address, const std::string& serverName)
	{
		testState.pairAndApproveServer(address, serverName);
	}

	void sendFiles(const Network::NetworkAddress& address, const std::string& serverName, const std::string& folderPath)
	{
		testState.sendFiles(address, serverName, folderPath);
	}

private:
	TestFullFileBackup testState;
};

extern "C" JNIEXPORT jlong JNICALL
Java_com_unnamed_easyphotobackup_TestFullFileBackup_create(
	JNIEnv* env,
	jobject /*this*/
)
{
	auto* obj = new TestFullFileBackupNative();
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

extern "C" JNIEXPORT void JNICALL
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
		return;
	}

	const char* serverNameChar = env->GetStringUTFChars(serverNameJStr, nullptr);
	const std::string serverName(serverNameChar);
	env->ReleaseStringUTFChars(serverNameJStr, serverNameChar);

	auto* obj = reinterpret_cast<TestFullFileBackupNative*>(handle);
	obj->pairAndApproveServer(*address, serverName);
}

extern "C" JNIEXPORT void JNICALL
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
		return;
	}

	const char* serverNameChar = env->GetStringUTFChars(serverNameJStr, nullptr);
	const std::string serverName(serverNameChar);
	env->ReleaseStringUTFChars(serverNameJStr, serverNameChar);

	const char* folderPathChar = env->GetStringUTFChars(folderPathJStr, nullptr);
	const std::string folderPath(folderPathChar);
	env->ReleaseStringUTFChars(folderPathJStr, folderPathChar);

	auto* obj = reinterpret_cast<TestFullFileBackupNative*>(handle);
	obj->sendFiles(*address, serverName, folderPath);
}
