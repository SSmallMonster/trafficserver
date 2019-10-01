#pragma once

#include <memory>

#include "wasm_vm.h"

namespace Wavm
{
std::unique_ptr<Wasm::WasmVm> createVm();

} // namespace Wavm
