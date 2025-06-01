export WASI_SDK_PATH=/opt/wasi-sdk
export CC="$WASI_SDK_PATH/bin/clang"
export CFLAGS="--sysroot=$WASI_SDK_PATH/share/wasi-sysroot"
