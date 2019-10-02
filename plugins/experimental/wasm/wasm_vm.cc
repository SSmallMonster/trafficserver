#include "wasm_vm.h"

#include <memory>

#ifdef WAVM_API
#include "wavm.h"
#endif

namespace Wasm
{
thread_local Wasm::Context *current_context_ = nullptr;
thread_local uint32_t effective_context_id_  = 0;

std::unique_ptr<WasmVm>
createWasmVm(std::string_view wasm_vm)
{
#ifdef WAVM_API
  if (wasm_vm == "wavm") {
    return Wavm::createVm();
  } else
#endif
  {
    throw WasmException(std::string("Failed to create WASM VM using ") + std::string(wasm_vm) +
                        " runtime. Envoy was compiled without support for it.");
  }
}

} // namespace Wasm
