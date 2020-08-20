APP_STL := c++_static
APP_CPPFLAGS += -fvisibility=hidden
APP_PLATFORM := android-19
APP_ABI := armeabi-v7a arm64-v8a

# temporarily open armeabi-v7a and --long-plt only
#APP_ABI := armeabi-v7a

APP_LDFLAGS := -llog

