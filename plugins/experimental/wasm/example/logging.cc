// NOLINT(namespace-envoy)
#include <string>

#include "proxy_wasm_intrinsics.h"

extern "C" EMSCRIPTEN_KEEPALIVE void proxy_onStart(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t)
{
  logTrace(std::string("test trace") + " logging");
  logDebug(std::string("test debug") + " logging");
  logError(std::string("test error") + " logging");
}
