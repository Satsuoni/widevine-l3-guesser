#include <stdint.h>
#include <emscripten/emscripten.h>
extern "C" {
    EMSCRIPTEN_KEEPALIVE const char* tryUsingDecoder(const char* input);
    EMSCRIPTEN_KEEPALIVE void freeStr(void* str);
}