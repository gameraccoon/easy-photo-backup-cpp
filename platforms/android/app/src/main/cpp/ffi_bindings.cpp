#include <jni.h>
#include <string>
#include <format>

extern "C" JNIEXPORT jstring JNICALL
Java_com_unnamed_easyphotobackup_MainActivity_stringFromJNI(
	JNIEnv* env,
	jobject /* this */)
{
	std::string hello = std::format("Hello from C++ {}", 10);
	return env->NewStringUTF(hello.c_str());
}
