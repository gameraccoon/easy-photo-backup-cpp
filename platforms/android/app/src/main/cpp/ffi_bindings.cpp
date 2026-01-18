#include <jni.h>
#include <string>
#include <format>

#include "client_shared/example/example.h"

extern "C" JNIEXPORT jstring JNICALL
Java_com_unnamed_easyphotobackup_MainActivity_stringFromJNI(
	JNIEnv* env,
	jobject /* this */)
{
	std::string hello = std::format("Hello from C++ {}", example::EXAMPLE_CLIENT_VALUE);
	return env->NewStringUTF(hello.c_str());
}
