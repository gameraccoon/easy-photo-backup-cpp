#include <format>
#include <string>

#include <jni.h>

extern "C" JNIEXPORT jstring JNICALL
Java_com_unnamed_easyphotobackup_MainActivity_stringFromJNI(
	JNIEnv* env,
	jobject /* this */
)
{
	std::string hello = std::format("Hello from C++ {}", 20);
	return env->NewStringUTF(hello.c_str());
}
