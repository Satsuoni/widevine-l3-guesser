#include <stdint.h>
#include <emscripten/emscripten.h>
extern "C" {
    EMSCRIPTEN_KEEPALIVE const char* guessInput(const char* input);
    EMSCRIPTEN_KEEPALIVE const char* getOutput(const char* input);
    EMSCRIPTEN_KEEPALIVE const char* getDeoaep(const char* input);
    EMSCRIPTEN_KEEPALIVE void freeStr(void* str);
}