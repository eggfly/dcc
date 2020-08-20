APP_STL := c++_static
APP_CPPFLAGS += -fvisibility=hidden
APP_PLATFORM := android-19

APP_ABI := armeabi-v7a arm64-v8a x86 x86_64
# temporarily open armeabi-v7a and --long-plt
#APP_ABI := armeabi-v7a

APP_LDFLAGS := -llog

