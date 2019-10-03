// NOLINT(namespace-envoy)
#include <string>

#include "proxy_wasm_intrinsics.h"

extern "C" EMSCRIPTEN_KEEPALIVE void proxy_onStart(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t)
{
  logTrace("onStart()");
}

extern "C" EMSCRIPTEN_KEEPALIVE int proxy_onRequestHeaders(uint32_t context_id) {
  logTrace("onRequestHeaders() context_id = " + std::to_string(context_id));
  return 0;
}
