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

extern "C" JNIEXPORT void JNICALL
Java_com_unnamed_easyphotobackup_TestFullFileBackup_getDiscoveryResultsNative(
	JNIEnv* env,
	jobject /*this*/,
	jlong handle
)
{
	auto* obj = reinterpret_cast<TestFullFileBackupNative*>(handle);
	obj->getDiscoveryResults();
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
	jstring ip,
	jint port
)
{
	//	auto* obj = reinterpret_cast<TestFullFileBackupNative*>(handle);

	const char* ipChar = env->GetStringUTFChars(ip, nullptr);
	std::optional<std::string> serverName = TestFullFileBackupNative::requestServerName(Network::NetworkAddress{
		.ip = std::string(ipChar),
		.port = static_cast<uint16_t>(port),
		.addressType = Network::AddressType::IpV4,
	});
	env->ReleaseStringUTFChars(ip, ipChar);

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
	jlong handle
)
{
	auto* obj = reinterpret_cast<TestFullFileBackupNative*>(handle);
	//obj->pairAndApproveServer();
}

extern "C" JNIEXPORT void JNICALL
Java_com_unnamed_easyphotobackup_TestFullFileBackup_sendFilesNative(
	JNIEnv* env,
	jobject /*this*/,
	jlong handle
)
{
	auto* obj = reinterpret_cast<TestFullFileBackupNative*>(handle);
	//obj->sendFilesNative();
}
