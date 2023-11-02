#include <jni.h>
#include <string>

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_test_1app_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}

extern "C" void mainfunc_init(void);

extern "C" JNIEXPORT void JNICALL
Java_com_example_test_1app_MainActivity_clientParamSet(
        JNIEnv* env,
        jobject /* this */) {

    mainfunc_init();
}

extern "C" void mainfunc_client_run(void);

extern "C" JNIEXPORT void JNICALL
Java_com_example_test_1app_MainActivity_clientStart(
        JNIEnv* env,
        jobject /* this */) {

    mainfunc_client_run();
}