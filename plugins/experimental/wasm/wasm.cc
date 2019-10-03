#include "wasm.h"

#include "ts/experimental.h"
#include "ts/ts.h"

#include <stdio.h>

#include <cmath>
#include <deque>
#include <limits>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>

#define WASM_DEBUG_TAG "wasm"

namespace Wasm {

// Any currently executing Wasm call context.
#define WASM_CONTEXT(_c)                                                                           \
  (ContextOrEffectiveContext(static_cast<Context*>((void)_c, current_context_)))
// The id of the context which should be used for calls out of the VM in place of current_context_
// above.

namespace {

inline Word wasmResultToWord(WasmResult r) { return Word(static_cast<uint64_t>(r)); }

inline uint32_t convertWordToUint32(Word w) { return static_cast<uint32_t>(w.u64_); }

// Convert a function of the form Word(Word...) to one of the form uint32_t(uint32_t...).
template <typename F, F* fn> struct ConvertFunctionWordToUint32 {
  static void convertFunctionWordToUint32() {}
};
template <typename R, typename... Args, auto (*F)(Args...)->R>
struct ConvertFunctionWordToUint32<R(Args...), F> {
  static auto convertFunctionWordToUint32(typename ConvertWordTypeToUint32<Args>::type... args) {
    return convertWordToUint32(F(std::forward<Args>(args)...));
  }
};
template <typename... Args, auto (*F)(Args...)->void>
struct ConvertFunctionWordToUint32<void(Args...), F> {
  static void convertFunctionWordToUint32(typename ConvertWordTypeToUint32<Args>::type... args) {
    F(std::forward<Args>(args)...);
  }
};

class SharedData {
public:
  WasmResult get(std::string_view vm_id, const std::string_view key,
                 std::pair<std::string, uint32_t>* result) {
    auto map = data.find(std::string(vm_id)); // thd std::string() could be avoided by using absl::flat_node_map
    if (map == data.end()) {
      return WasmResult::NotFound;
    }
    auto it = map->second.find(std::string(key));
    if (it != map->second.end()) {
      *result = it->second;
      return WasmResult::Ok;
    }
    return WasmResult::NotFound;
  }

  WasmResult set(std::string_view vm_id, std::string_view key, std::string_view value,
                 uint32_t cas) {
    std::unordered_map<std::string, std::pair<std::string, uint32_t>>* map;
    auto string_vm_id = std::string(vm_id);
    auto map_it = data.find(string_vm_id);
    if (map_it == data.end()) {
      map = &data[string_vm_id];
    } else {
      map = &map_it->second;
    }
    auto it = map->find(std::string(key));
    if (it != map->end()) {
      if (cas && cas != it->second.second) {
        return WasmResult::CasMismatch;
      }
      it->second = std::make_pair(std::string(value), nextCas());
    } else {
      map->emplace(key, std::make_pair(std::string(value), nextCas()));
    }
    return WasmResult::Ok;
  }

  uint32_t registerQueue(std::string_view vm_id, std::string_view queue_name, uint32_t context_id,
      TSEventThread thread) {
    auto key = std::make_pair(std::string(vm_id), std::string(queue_name));
    auto it = queue_tokens.insert(std::make_pair(key, static_cast<uint32_t>(0)));
    if (it.second) {
      it.first->second = nextQueueToken();
      queue_token_set.insert(it.first->second);
    }
    uint32_t token = it.first->second;
    auto& q = queues[token];
    q.vm_id = std::string(vm_id);
    q.context_id = context_id;
    q.thread = thread;
    // Preserve any existing data.
    return token;
  }

  uint32_t resolveQueue(std::string_view vm_id, std::string_view queue_name) {
    auto key = std::make_pair(std::string(vm_id), std::string(queue_name));
    auto it = queue_tokens.find(key);
    if (it != queue_tokens.end()) {
      return it->second;
    }
    return 0; // N.B. zero indicates that the queue was not found.
  }

  WasmResult dequeue(uint32_t token, std::string* data) {
    auto it = queues.find(token);
    if (it == queues.end()) {
      return WasmResult::NotFound;
    }
    if (it->second.queue.empty()) {
      return WasmResult::Empty;
    }
    *data = it->second.queue.front();
    it->second.queue.pop_front();
    return WasmResult::Ok;
  }

  WasmResult enqueue(uint32_t token, std::string_view value) {
    auto it = queues.find(token);
    if (it == queues.end()) {
      return WasmResult::NotFound;
    }
    it->second.queue.push_back(std::string(value));
#if 0
    auto vm_id = it->second.vm_id;
    auto context_id = it->second.context_id;
    it->second.thread->post([vm_id, context_id, token] {
      auto wasm = getThreadLocalWasmOrNull(vm_id);
      if (wasm) {
        wasm->queueReady(context_id, token);
      }
    });
#endif
    return WasmResult::Ok;
  }

  uint32_t nextCas() {
    auto result = cas;
    cas++;
    if (!cas) { // 0 is not a valid CAS value.
      cas++;
    }
    return result;
  }

private:
  uint32_t nextQueueToken() {
    while (true) {
      uint32_t token = next_queue_token++;
      if (token == 0) {
        continue; // 0 is an illegal token.
      }
      if (queue_token_set.find(token) == queue_token_set.end()) {
        return token;
      }
    }
  }

  struct Queue {
    std::string vm_id;
    uint32_t context_id;
    TSEventThread thread;
    std::deque<std::string> queue;
  };

  // TODO add a mutex when this is shared between threads.
  uint32_t cas = 1;
  uint32_t next_queue_token = 1;
  std::map<std::string, std::unordered_map<std::string, std::pair<std::string, uint32_t>>>
      data;
  std::map<uint32_t, Queue> queues;
  struct pair_hash {
    template <class T1, class T2> std::size_t operator()(const std::pair<T1, T2>& pair) const {
      return std::hash<T1>()(pair.first) ^ std::hash<T2>()(pair.second);
    }
  };
  std::unordered_map<std::pair<std::string, std::string>, uint32_t, pair_hash> queue_tokens;
  std::unordered_set<uint32_t> queue_token_set;
};

SharedData global_shared_data;

// Map from Wasm ID to the local Wasm instance.
thread_local std::unordered_map<std::string, std::shared_ptr<Wasm>> local_wasms;

const std::string INLINE_STRING = "<inline>";

template <typename Pairs> size_t pairsSize(const Pairs& result) {
  size_t size = 4; // number of headers
  for (auto& p : result) {
    size += 8;                   // size of key, size of value
    size += p.first.size() + 1;  // null terminated key
    size += p.second.size() + 1; // null terminated value
  }
  return size;
}

template <typename Pairs> void marshalPairs(const Pairs& result, char* buffer) {
  char* b = buffer;
  *reinterpret_cast<uint32_t*>(b) = result.size();
  b += sizeof(uint32_t);
  for (auto& p : result) {
    *reinterpret_cast<uint32_t*>(b) = p.first.size();
    b += sizeof(uint32_t);
    *reinterpret_cast<uint32_t*>(b) = p.second.size();
    b += sizeof(uint32_t);
  }
  for (auto& p : result) {
    memcpy(b, p.first.data(), p.first.size());
    b += p.first.size();
    *b++ = 0;
    memcpy(b, p.second.data(), p.second.size());
    b += p.second.size();
    *b++ = 0;
  }
}

Pairs toPairs(std::string_view buffer) {
  Pairs result;
  const char* b = buffer.data();
  if (buffer.size() < sizeof(uint32_t)) {
    return {};
  }
  auto size = *reinterpret_cast<const uint32_t*>(b);
  b += sizeof(uint32_t);
  if (sizeof(uint32_t) + size * 2 * sizeof(uint32_t) > buffer.size()) {
    return {};
  }
  result.resize(size);
  for (uint32_t i = 0; i < size; i++) {
    result[i].first = std::string_view(nullptr, *reinterpret_cast<const uint32_t*>(b));
    b += sizeof(uint32_t);
    result[i].second = std::string_view(nullptr, *reinterpret_cast<const uint32_t*>(b));
    b += sizeof(uint32_t);
  }
  for (auto& p : result) {
    p.first = std::string_view(b, p.first.size());
    b += p.first.size() + 1;
    p.second = std::string_view(b, p.second.size());
    b += p.second.size() + 1;
  }
  return result;
}

template <typename Pairs>
bool getPairs(Context* context, const Pairs& result, uint64_t ptr_ptr, uint64_t size_ptr) {
  if (result.empty()) {
    return context->wasm()->copyToPointerSize("", ptr_ptr, size_ptr);
  }
  uint64_t size = pairsSize(result);
  uint64_t ptr;
  char* buffer = static_cast<char*>(context->wasm()->allocMemory(size, &ptr));
  marshalPairs(result, buffer);
  if (!context->wasmVm()->setWord(ptr_ptr, Word(ptr))) {
    return false;
  }
  if (!context->wasmVm()->setWord(size_ptr, Word(size))) {
    return false;
  }
  return true;
}

void exportPairs(Context* context, const Pairs& pairs, uint64_t* ptr_ptr, uint64_t* size_ptr) {
  if (pairs.empty()) {
    *ptr_ptr = 0;
    *size_ptr = 0;
    return;
  }
  uint64_t size = pairsSize(pairs);
  char* buffer = static_cast<char*>(context->wasm()->allocMemory(size, ptr_ptr));
  marshalPairs(pairs, buffer);
  *size_ptr = size;
}

#if 0
HeaderMap buildHeaderMapFromPairs(const Pairs& pairs) {
  HeaderMap map;
  for (auto& p : pairs) {
    map[std::string(p.first)] = std::string(p.second);
  }
  return map;
}
#endif

const uint8_t* decodeVarint(const uint8_t* pos, const uint8_t* end, uint32_t* out) {
  uint32_t ret = 0;
  int shift = 0;
  while (pos < end && (*pos & 0x80)) {
    ret |= (*pos & 0x7f) << shift;
    shift += 7;
    pos++;
  }
  if (pos < end) {
    ret |= *pos << shift;
    pos++;
  }
  *out = ret;
  return pos;
}

Context* ContextOrEffectiveContext(Context* context) {
  if (effective_context_id_ == 0) {
    return context;
  }
  auto effective_context = context->wasm()->getContext(effective_context_id_);
  if (effective_context) {
    return effective_context;
  }
  // The effective_context_id_ no longer exists, revert to the true context.
  return context;
}

} // namespace

// Test support.

uint32_t resolveQueueForTest(std::string_view vm_id, std::string_view queue_name) {
  return global_shared_data.resolveQueue(vm_id, queue_name);
}

//
// HTTP Handlers
//

Word setPropertyHandler(void* raw_context, Word key_ptr, Word key_size, Word value_ptr,
                        Word value_size) {
  auto context = WASM_CONTEXT(raw_context);
  auto key = context->wasmVm()->getMemory(key_ptr.u64_, key_size.u64_);
  auto value = context->wasmVm()->getMemory(value_ptr.u64_, value_size.u64_);
  if (!key || !value) {
    return wasmResultToWord(WasmResult::InvalidMemoryAccess);
  }
  return wasmResultToWord(context->setProperty(key.value(), value.value()));
}

// Generic selector
Word getPropertyHandler(void* raw_context, Word path_ptr, Word path_size, Word value_ptr_ptr,
                        Word value_size_ptr) {
  auto context = WASM_CONTEXT(raw_context);
  auto path = context->wasmVm()->getMemory(path_ptr.u64_, path_size.u64_);
  if (!path.has_value()) {
    return wasmResultToWord(WasmResult::InvalidMemoryAccess);
  }
  std::string value;
  auto result = context->getProperty(path.value(), &value);
  if (result != WasmResult::Ok) {
    return wasmResultToWord(result);
  }
  if (!context->wasm()->copyToPointerSize(value, value_ptr_ptr.u64_, value_size_ptr.u64_)) {
    return wasmResultToWord(WasmResult::InvalidMemoryAccess);
  }
  return wasmResultToWord(WasmResult::Ok);
}

// Continue/Reply/Route
Word continueRequestHandler(void* raw_context) {
  auto context = WASM_CONTEXT(raw_context);
  context->continueRequest();
  return wasmResultToWord(WasmResult::Ok);
}

Word continueResponseHandler(void* raw_context) {
  auto context = WASM_CONTEXT(raw_context);
  context->continueResponse();
  return wasmResultToWord(WasmResult::Ok);
}

Word sendLocalResponseHandler(void* raw_context, Word response_code, Word response_code_details_ptr,
                              Word response_code_details_size, Word body_ptr, Word body_size,
                              Word additional_response_header_pairs_ptr,
                              Word additional_response_header_pairs_size) {
  auto context = WASM_CONTEXT(raw_context);
  auto details =
      context->wasmVm()->getMemory(response_code_details_ptr.u64_, response_code_details_size.u64_);
  auto body = context->wasmVm()->getMemory(body_ptr.u64_, body_size.u64_);
  auto additional_response_header_pairs = context->wasmVm()->getMemory(
      additional_response_header_pairs_ptr.u64_, additional_response_header_pairs_size.u64_);
  if (!details || !body || !additional_response_header_pairs) {
    return wasmResultToWord(WasmResult::InvalidMemoryAccess);
  }
  auto additional_headers = toPairs(additional_response_header_pairs.value());
  context->sendLocalResponse(response_code.u64_, body.value(), additional_headers);
  return wasmResultToWord(WasmResult::Ok);
}

Word setEffectiveContextHandler(void* raw_context, Word context_id) {
  auto context = WASM_CONTEXT(raw_context);
  uint32_t cid = static_cast<uint32_t>(context_id.u64_);
  auto c = context->wasm()->getContext(cid);
  if (!c) {
    return wasmResultToWord(WasmResult::BadArgument);
  }
  effective_context_id_ = cid;
  return wasmResultToWord(WasmResult::Ok);
}

Word clearRouteCacheHandler(void* raw_context) {
  (void)raw_context;
  // Noop.
  return wasmResultToWord(WasmResult::Ok);
}

// SharedData
Word getSharedDataHandler(void* raw_context, Word key_ptr, Word key_size, Word value_ptr_ptr,
                          Word value_size_ptr, Word cas_ptr) {
  auto context = WASM_CONTEXT(raw_context);
  auto key = context->wasmVm()->getMemory(key_ptr.u64_, key_size.u64_);
  if (!key) {
    return wasmResultToWord(WasmResult::InvalidMemoryAccess);
  }
  std::pair<std::string, uint32_t> data;
  WasmResult result = context->getSharedData(key.value(), &data);
  if (result != WasmResult::Ok) {
    return wasmResultToWord(result);
  }
  if (!context->wasm()->copyToPointerSize(data.first, value_ptr_ptr.u64_, value_size_ptr.u64_)) {
    return wasmResultToWord(WasmResult::InvalidMemoryAccess);
  }
  if (!context->wasmVm()->setMemory(cas_ptr.u64_, sizeof(uint32_t), &data.second)) {
    return wasmResultToWord(WasmResult::InvalidMemoryAccess);
  }
  return wasmResultToWord(WasmResult::Ok);
}

Word setSharedDataHandler(void* raw_context, Word key_ptr, Word key_size, Word value_ptr,
                          Word value_size, Word cas) {
  auto context = WASM_CONTEXT(raw_context);
  auto key = context->wasmVm()->getMemory(key_ptr.u64_, key_size.u64_);
  auto value = context->wasmVm()->getMemory(value_ptr.u64_, value_size.u64_);
  if (!key || !value) {
    return wasmResultToWord(WasmResult::InvalidMemoryAccess);
  }
  return wasmResultToWord(context->setSharedData(key.value(), value.value(), cas.u64_));
}

Word registerSharedQueueHandler(void* raw_context, Word queue_name_ptr, Word queue_name_size,
                                Word token_ptr) {
  auto context = WASM_CONTEXT(raw_context);
  auto queue_name = context->wasmVm()->getMemory(queue_name_ptr.u64_, queue_name_size.u64_);
  if (!queue_name) {
    return wasmResultToWord(WasmResult::InvalidMemoryAccess);
  }
  uint32_t token = context->registerSharedQueue(queue_name.value());
  if (!context->wasm()->setDatatype(token_ptr.u64_, token)) {
    return wasmResultToWord(WasmResult::InvalidMemoryAccess);
  }
  return wasmResultToWord(WasmResult::Ok);
}

Word dequeueSharedQueueHandler(void* raw_context, Word token, Word data_ptr_ptr,
                               Word data_size_ptr) {
  auto context = WASM_CONTEXT(raw_context);
  std::string data;
  WasmResult result = context->dequeueSharedQueue(token.u32(), &data);
  if (result != WasmResult::Ok) {
    return wasmResultToWord(result);
  }
  if (!context->wasm()->copyToPointerSize(data, data_ptr_ptr.u64_, data_size_ptr.u64_)) {
    return wasmResultToWord(WasmResult::InvalidMemoryAccess);
  }
  return wasmResultToWord(WasmResult::Ok);
}

Word resolveSharedQueueHandler(void* raw_context, Word vm_id_ptr, Word vm_id_size,
                               Word queue_name_ptr, Word queue_name_size, Word token_ptr) {
  auto context = WASM_CONTEXT(raw_context);
  auto vm_id = context->wasmVm()->getMemory(vm_id_ptr.u64_, vm_id_size.u64_);
  auto queue_name = context->wasmVm()->getMemory(queue_name_ptr.u64_, queue_name_size.u64_);
  if (!vm_id || !queue_name) {
    return wasmResultToWord(WasmResult::InvalidMemoryAccess);
  }
  uint32_t token = 0;
  auto result = context->resolveSharedQueue(vm_id.value(), queue_name.value(), &token);
  if (result != WasmResult::Ok) {
    return wasmResultToWord(result);
  }
  if (!context->wasm()->setDatatype(token_ptr.u64_, token)) {
    return wasmResultToWord(WasmResult::InvalidMemoryAccess);
  }
  return wasmResultToWord(WasmResult::Ok);
}

Word enqueueSharedQueueHandler(void* raw_context, Word token, Word data_ptr, Word data_size) {
  auto context = WASM_CONTEXT(raw_context);
  auto data = context->wasmVm()->getMemory(data_ptr.u64_, data_size.u64_);
  if (!data) {
    return wasmResultToWord(WasmResult::InvalidMemoryAccess);
  }
  return wasmResultToWord(context->enqueueSharedQueue(token.u32(), data.value()));
}

// Header/Trailer/Metadata Maps
Word addHeaderMapValueHandler(void* raw_context, Word type, Word key_ptr, Word key_size,
                              Word value_ptr, Word value_size) {
  if (type.u64_ > static_cast<uint64_t>(HeaderMapType::MAX)) {
    return wasmResultToWord(WasmResult::BadArgument);
  }
  auto context = WASM_CONTEXT(raw_context);
  auto key = context->wasmVm()->getMemory(key_ptr.u64_, key_size.u64_);
  auto value = context->wasmVm()->getMemory(value_ptr.u64_, value_size.u64_);
  if (!key || !value) {
    return wasmResultToWord(WasmResult::InvalidMemoryAccess);
  }
  context->addHeaderMapValue(static_cast<HeaderMapType>(type.u64_), key.value(), value.value());
  return wasmResultToWord(WasmResult::Ok);
}

Word getHeaderMapValueHandler(void* raw_context, Word type, Word key_ptr, Word key_size,
                              Word value_ptr_ptr, Word value_size_ptr) {
  if (type.u64_ > static_cast<uint64_t>(HeaderMapType::MAX)) {
    return wasmResultToWord(WasmResult::BadArgument);
  }
  auto context = WASM_CONTEXT(raw_context);
  auto key = context->wasmVm()->getMemory(key_ptr.u64_, key_size.u64_);
  if (!key) {
    return wasmResultToWord(WasmResult::InvalidMemoryAccess);
  }
  auto result = context->getHeaderMapValue(static_cast<HeaderMapType>(type.u64_), key.value());
  context->wasm()->copyToPointerSize(result, value_ptr_ptr.u64_, value_size_ptr.u64_);
  return wasmResultToWord(WasmResult::Ok);
}

Word replaceHeaderMapValueHandler(void* raw_context, Word type, Word key_ptr, Word key_size,
                                  Word value_ptr, Word value_size) {
  if (type.u64_ > static_cast<uint64_t>(HeaderMapType::MAX)) {
    return wasmResultToWord(WasmResult::BadArgument);
  }
  auto context = WASM_CONTEXT(raw_context);
  auto key = context->wasmVm()->getMemory(key_ptr.u64_, key_size.u64_);
  auto value = context->wasmVm()->getMemory(value_ptr.u64_, value_size.u64_);
  if (!key || !value) {
    return wasmResultToWord(WasmResult::InvalidMemoryAccess);
  }
  context->replaceHeaderMapValue(static_cast<HeaderMapType>(type.u64_), key.value(), value.value());
  return wasmResultToWord(WasmResult::Ok);
}

Word removeHeaderMapValueHandler(void* raw_context, Word type, Word key_ptr, Word key_size) {
  if (type.u64_ > static_cast<uint64_t>(HeaderMapType::MAX)) {
    return wasmResultToWord(WasmResult::BadArgument);
  }
  auto context = WASM_CONTEXT(raw_context);
  auto key = context->wasmVm()->getMemory(key_ptr.u64_, key_size.u64_);
  if (!key) {
    return wasmResultToWord(WasmResult::InvalidMemoryAccess);
  }
  context->removeHeaderMapValue(static_cast<HeaderMapType>(type.u64_), key.value());
  return wasmResultToWord(WasmResult::Ok);
}

Word getHeaderMapPairsHandler(void* raw_context, Word type, Word ptr_ptr, Word size_ptr) {
  if (type.u64_ > static_cast<uint64_t>(HeaderMapType::MAX)) {
    return wasmResultToWord(WasmResult::BadArgument);
  }
  auto context = WASM_CONTEXT(raw_context);
  auto result = context->getHeaderMapPairs(static_cast<HeaderMapType>(type.u64_));
  if (!getPairs(context, result, ptr_ptr.u64_, size_ptr.u64_)) {
    return wasmResultToWord(WasmResult::InvalidMemoryAccess);
  }
  return wasmResultToWord(WasmResult::Ok);
}

Word setHeaderMapPairsHandler(void* raw_context, Word type, Word ptr, Word size) {
  if (type.u64_ > static_cast<uint64_t>(HeaderMapType::MAX)) {
    return wasmResultToWord(WasmResult::BadArgument);
  }
  auto context = WASM_CONTEXT(raw_context);
  auto data = context->wasmVm()->getMemory(ptr.u64_, size.u64_);
  if (!data) {
    return wasmResultToWord(WasmResult::InvalidMemoryAccess);
  }
  context->setHeaderMapPairs(static_cast<HeaderMapType>(type.u64_), toPairs(data.value()));
  return wasmResultToWord(WasmResult::Ok);
}

Word getHeaderMapSizeHandler(void* raw_context, Word type, Word result_ptr) {
  if (type.u64_ > static_cast<uint64_t>(HeaderMapType::MAX)) {
    return wasmResultToWord(WasmResult::BadArgument);
  }
  auto context = WASM_CONTEXT(raw_context);
  size_t result = context->getHeaderMapSize(static_cast<HeaderMapType>(type.u64_));
  if (!context->wasmVm()->setWord(result_ptr.u64_, Word(result))) {
    return wasmResultToWord(WasmResult::InvalidMemoryAccess);
  }
  return wasmResultToWord(WasmResult::Ok);
}

// Body Buffer
Word getRequestBodyBufferBytesHandler(void* raw_context, Word start, Word length, Word ptr_ptr,
                                      Word size_ptr) {
  auto context = WASM_CONTEXT(raw_context);
  auto result = context->getRequestBodyBufferBytes(start.u64_, length.u64_);
  context->wasm()->copyToPointerSize(result, ptr_ptr.u64_, size_ptr.u64_);
  return wasmResultToWord(WasmResult::Ok);
}

Word getResponseBodyBufferBytesHandler(void* raw_context, Word start, Word length, Word ptr_ptr,
                                       Word size_ptr) {
  auto context = WASM_CONTEXT(raw_context);
  auto result = context->getResponseBodyBufferBytes(start.u64_, length.u64_);
  context->wasm()->copyToPointerSize(result, ptr_ptr.u64_, size_ptr.u64_);
  return wasmResultToWord(WasmResult::Ok);
}

Word httpCallHandler(void* raw_context, Word uri_ptr, Word uri_size, Word header_pairs_ptr,
                     Word header_pairs_size, Word body_ptr, Word body_size, Word trailer_pairs_ptr,
                     Word trailer_pairs_size, Word timeout_milliseconds) {
  auto context = WASM_CONTEXT(raw_context)->root_context();
  auto uri = context->wasmVm()->getMemory(uri_ptr.u64_, uri_size.u64_);
  auto body = context->wasmVm()->getMemory(body_ptr.u64_, body_size.u64_);
  auto header_pairs = context->wasmVm()->getMemory(header_pairs_ptr.u64_, header_pairs_size.u64_);
  auto trailer_pairs =
      context->wasmVm()->getMemory(trailer_pairs_ptr.u64_, trailer_pairs_size.u64_);
  if (!uri || !body || !header_pairs || !trailer_pairs) {
    return wasmResultToWord(WasmResult::InvalidMemoryAccess);
  }
  auto headers = toPairs(header_pairs.value());
  auto trailers = toPairs(trailer_pairs.value());
  return context->httpCall(uri.value(), headers, body.value(), trailers, timeout_milliseconds.u64_);
}

Word defineMetricHandler(void* raw_context, Word metric_type, Word name_ptr, Word name_size,
                         Word metric_id_ptr) {
  if (metric_type.u64_ > static_cast<uint64_t>(Context::MetricType::Max)) {
    return 0;
  }
  auto context = WASM_CONTEXT(raw_context);
  auto name = context->wasmVm()->getMemory(name_ptr.u64_, name_size.u64_);
  if (!name) {
    return wasmResultToWord(WasmResult::InvalidMemoryAccess);
  }
  uint32_t metric_id = 0;
  auto result = context->defineMetric(static_cast<Context::MetricType>(metric_type.u64_),
                                      name.value(), &metric_id);
  if (result != WasmResult::Ok) {
    return wasmResultToWord(result);
  }
  if (!context->wasm()->setDatatype(metric_id_ptr.u64_, metric_id)) {
    return wasmResultToWord(WasmResult::InvalidMemoryAccess);
  }
  return wasmResultToWord(WasmResult::Ok);
}

Word incrementMetricHandler(void* raw_context, Word metric_id, int64_t offset) {
  auto context = WASM_CONTEXT(raw_context);
  return wasmResultToWord(context->incrementMetric(metric_id.u64_, offset));
}

Word recordMetricHandler(void* raw_context, Word metric_id, uint64_t value) {
  auto context = WASM_CONTEXT(raw_context);
  return wasmResultToWord(context->recordMetric(metric_id.u64_, value));
}

Word getMetricHandler(void* raw_context, Word metric_id, Word result_uint64_ptr) {
  auto context = WASM_CONTEXT(raw_context);
  uint64_t value = 0;
  auto result = context->getMetric(metric_id.u64_, &value);
  if (result != WasmResult::Ok) {
    return wasmResultToWord(result);
  }
  if (!context->wasm()->setDatatype(result_uint64_ptr.u64_, value)) {
    return wasmResultToWord(WasmResult::InvalidMemoryAccess);
  }
  return wasmResultToWord(WasmResult::Ok);
}

Word _emscripten_get_heap_sizeHandler(void* raw_context) {
  auto context = WASM_CONTEXT(raw_context);
  return context->wasmVm()->getMemorySize();
}

Word _emscripten_memcpy_bigHandler(void* raw_context, Word dst, Word src, Word size) {
  auto context = WASM_CONTEXT(raw_context);
  auto data = context->wasmVm()->getMemory(src.u64_, size.u64_);
  if (!data) {
    return 0;
  }
  context->wasmVm()->setMemory(dst.u64_, size.u64_, data.value().data());
  return dst;
}

Word _emscripten_resize_heapHandler(void*, Word) {
  throw WasmException("emscripten emscripten_resize_heap");
}

Word abortOnCannotGrowMemoryAbi00Handler(void*) {
  throw WasmException("emscripten abortOnCannotGrowMemory");
}

Word abortOnCannotGrowMemoryAbi02Handler(void*, Word) {
  throw WasmException("emscripten abortOnCannotGrowMemory");
}

void abortHandler(void*, Word) { throw WasmException("emscripten abort"); }

void _abortHandler(void*) { throw WasmException("emscripten abort"); }

void _llvm_trapHandler(void*) { throw WasmException("emscripten llvm_trap"); }

void ___assert_failHandler(void*, Word, Word, Word, Word) {
  throw WasmException("emscripten assert_fail");
}

void ___cxa_throwHandler(void*, Word, Word, Word) { throw WasmException("emscripten cxa_throw"); }

void ___cxa_pure_virtualHandler(void*) { throw WasmException("emscripten cxa_pure_virtual"); }

Word ___call_mainHandler(void*, Word, Word) { throw WasmException("emscripten call_main"); }

Word ___cxa_allocate_exceptionHandler(void*, Word) {
  throw WasmException("emscripten cxa_allocate_exception");
}

Word ___cxa_uncaught_exceptionHandler(void*) {
  throw WasmException("emscripten cxa_uncaught_exception");
}

Word ___cxa_uncaught_exceptionsHandler(void*) {
  throw WasmException("emscripten cxa_uncaught_exceptions");
}

Word ___clock_gettimeHandler(void*, Word, Word) { throw WasmException("emscripten clock_gettime"); }

void ___lockHandler(void*, Word) { throw WasmException("emscripten lock"); }

void ___unlockHandler(void*, Word) { throw WasmException("emscripten unlock"); }

Word ___syscall6Handler(void*, Word, Word) { throw WasmException("emscripten syscall6"); }

Word ___syscall54Handler(void*, Word, Word) { throw WasmException("emscripten syscall54"); }

Word ___syscall140Handler(void*, Word, Word) { throw WasmException("emscripten syscall140"); }

// Implementation of writev-like() syscall that redirects stdout/stderr to Envoy logs.
Word writevImpl(void* raw_context, Word fd, Word iovs, Word iovs_len, Word* nwritten_ptr) {
  auto context = WASM_CONTEXT(raw_context);

  // Read syscall args.
  LogLevel log_level;
  switch (fd.u64_) {
  case 1 /* stdout */:
    log_level = LogLevel::info;
    break;
  case 2 /* stderr */:
    log_level = LogLevel::error;
    break;
  default:
    return 8; // __WASI_EBADF
  }

  std::string s;
  for (size_t i = 0; i < iovs_len.u64_; i++) {
    auto memslice =
        context->wasmVm()->getMemory(iovs.u64_ + i * 2 * sizeof(uint32_t), 2 * sizeof(uint32_t));
    if (!memslice) {
      context->wasm()->setErrno(EINVAL);
      return 21; // __WASI_EFAULT
    }
    const uint32_t* iovec = reinterpret_cast<const uint32_t*>(memslice.value().data());
    if (iovec[1] /* buf_len */) {
      memslice = context->wasmVm()->getMemory(iovec[0] /* buf */, iovec[1] /* buf_len */);
      if (!memslice) {
        context->wasm()->setErrno(EINVAL);
        return 21; // __WASI_EFAULT
      }
      s.append(memslice.value().data(), memslice.value().size());
    }
  }

  size_t written = s.size();
  if (written) {
    // Remove trailing newline from the logs, if any.
    if (s[written - 1] == '\n') {
      s.erase(written - 1);
    }
    context->scriptLog(log_level, s);
  }
  *nwritten_ptr = Word(written);
  return 0; // __WASI_ESUCCESS
}

// ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
Word ___syscall146Handler(void* raw_context, Word, Word syscall_args_ptr) {
  auto context = WASM_CONTEXT(raw_context);

  // Read syscall args.
  auto memslice = context->wasmVm()->getMemory(syscall_args_ptr.u64_, 3 * sizeof(uint32_t));
  if (!memslice) {
    context->wasm()->setErrno(EINVAL);
    return -1;
  }
  const uint32_t* syscall_args = reinterpret_cast<const uint32_t*>(memslice.value().data());

  Word nwritten(0);
  auto result = writevImpl(raw_context, Word(syscall_args[0]), Word(syscall_args[1]),
                           Word(syscall_args[2]), &nwritten);
  if (result.u64_ != 0) { // __WASI_ESUCCESS
    return -1;
  }
  return nwritten;
}

// _was_errno_t _wasi_fd_write(_wasi_fd_t fd, const _wasi_ciovec_t *iov, size_t iovs_len, size_t*
// nwritten);
Word ___wasi_fd_writeHandler(void* raw_context, Word fd, Word iovs, Word iovs_len,
                             Word nwritten_ptr) {
  auto context = WASM_CONTEXT(raw_context);

  Word nwritten(0);
  auto result = writevImpl(raw_context, fd, iovs, iovs_len, &nwritten);
  if (result.u64_ != 0) { // __WASI_ESUCCESS
    return result;
  }
  if (!context->wasmVm()->setWord(nwritten_ptr.u64_, Word(nwritten))) {
    return 21; // __WASI_EFAULT
  }
  return 0; // __WASI_ESUCCESS
}

void ___setErrNoHandler(void*, Word) { throw WasmException("emscripten setErrNo"); }

Word _pthread_equalHandler(void*, Word left, Word right) { return left.u64_ == right.u64_; }
// NB: pthread_mutex_destroy is required to return 0 by the protobuf libarary.
Word _pthread_mutex_destroyHandler(void*, Word) { return 0; }
Word _pthread_cond_waitHandler(void*, Word, Word) {
  throw WasmException("emscripten pthread_cond_wait");
}
Word _pthread_getspecificHandler(void*, Word) {
  throw WasmException("emscripten pthread_getspecific");
}
Word _pthread_key_createHandler(void*, Word, Word) {
  throw WasmException("emscripten pthread_key_create");
}
Word _pthread_onceHandler(void*, Word, Word) { throw WasmException("emscripten pthread_once"); }
Word _pthread_setspecificHandler(void*, Word, Word) {
  throw WasmException("emscripten pthread_setspecific");
}
void setTempRet0Handler(void*, Word) { throw WasmException("emscripten setTempRet0"); }

double globalMathLogHandler(void*, double f) { return ::log(f); }

Word setTickPeriodMillisecondsHandler(void* raw_context, Word tick_period_milliseconds) {
  return wasmResultToWord(
      WASM_CONTEXT(raw_context)
          ->setTickPeriod(tick_period_milliseconds.u64_ * 1000 * 1000)); // -> nsec
}

Word getCurrentTimeNanosecondsHandler(void* raw_context, Word result_uint64_ptr) {
  auto context = WASM_CONTEXT(raw_context);
  uint64_t result = context->getCurrentTimeNanoseconds();
  if (!context->wasm()->setDatatype(result_uint64_ptr.u64_, result)) {
    return wasmResultToWord(WasmResult::InvalidMemoryAccess);
  }
  return wasmResultToWord(WasmResult::Ok);
}

Word logHandler(void* raw_context, Word level, Word address, Word size) {
  auto context = WASM_CONTEXT(raw_context);
  auto message = context->wasmVm()->getMemory(address.u64_, size.u64_);
  if (!message) {
    return wasmResultToWord(WasmResult::InvalidMemoryAccess);
  }
  context->scriptLog(static_cast<LogLevel>(level.u64_), message.value());
  return wasmResultToWord(WasmResult::Ok);
}

WasmResult Context::setTickPeriod(uint64_t tick_period) {
  wasm_->setTickPeriod(root_context_id_ ? root_context_id_ : id_, tick_period);
  return WasmResult::Ok;
}

uint64_t Context::getCurrentTimeNanoseconds() {
  return TSHRTime();
}

WasmResult Context::getProperty(std::string_view path, std::string* result) {
  return WasmResult::NotFound;
}

// Shared Data
WasmResult Context::getSharedData(std::string_view key, std::pair<std::string, uint32_t>* data) {
  return global_shared_data.get(wasm_->id(), key, data);
}

WasmResult Context::setSharedData(std::string_view key, std::string_view value, uint32_t cas) {
  return global_shared_data.set(wasm_->id(), key, value, cas);
}

// Shared Queue

uint32_t Context::registerSharedQueue(std::string_view queue_name) {
  // Get the id of the root context if this is a stream context because onQueueReady is on the root.
  return global_shared_data.registerQueue(
      wasm_->id(), queue_name, isRootContext() ? id_ : root_context_id_, TSEventThreadSelf());
}

WasmResult Context::resolveSharedQueue(std::string_view vm_id, std::string_view queue_name,
                                       uint32_t* token_ptr) {
  uint32_t token = global_shared_data.resolveQueue(vm_id, queue_name);
  if (!token) {
    return WasmResult::NotFound;
  }
  *token_ptr = token;
  return WasmResult::Ok;
}

WasmResult Context::dequeueSharedQueue(uint32_t token, std::string* data) {
  return global_shared_data.dequeue(token, data);
}

WasmResult Context::enqueueSharedQueue(uint32_t token, std::string_view value) {
  return global_shared_data.enqueue(token, value);
}

// Header/Trailer/Metadata Maps.
HeaderMap* Context::getMap(HeaderMapType type) {
  switch (type) {
  case HeaderMapType::RequestHeaders:
    return nullptr;
  case HeaderMapType::RequestTrailers:
    return nullptr;
  case HeaderMapType::ResponseHeaders:
    return nullptr;
  case HeaderMapType::ResponseTrailers:
    return nullptr;
  default:
  case HeaderMapType::GrpcCreateInitialMetadata:
  case HeaderMapType::GrpcReceiveInitialMetadata:
    return nullptr;
  }
}

const HeaderMap* Context::getConstMap(HeaderMapType type) {
  switch (type) {
  case HeaderMapType::RequestHeaders:
    return nullptr;
  case HeaderMapType::RequestTrailers:
    return nullptr;
  case HeaderMapType::ResponseHeaders:
    return nullptr;
  case HeaderMapType::ResponseTrailers:
    return nullptr;
  default:
  case HeaderMapType::GrpcCreateInitialMetadata:
  case HeaderMapType::GrpcReceiveInitialMetadata:
    return nullptr;
  }
}

void Context::addHeaderMapValue(HeaderMapType type, std::string_view key,
                                std::string_view value) {
  auto map = getMap(type);
  if (!map) {
    return;
  }
}

std::string_view Context::getHeaderMapValue(HeaderMapType type, std::string_view key) {
  auto map = getConstMap(type);
  if (!map) {
    return "";
  }
  return "";
}

Pairs headerMapToPairs(const HeaderMap* map) {
  if (!map) {
    return {};
  }
  Pairs pairs;
  pairs.reserve(map->size());
  return pairs;
}

Pairs Context::getHeaderMapPairs(HeaderMapType type) { return headerMapToPairs(getConstMap(type)); }

void Context::setHeaderMapPairs(HeaderMapType type, const Pairs& pairs) {
  auto map = getMap(type);
  if (!map) {
    return;
  }
}

void Context::removeHeaderMapValue(HeaderMapType type, std::string_view key) {
  auto map = getMap(type);
  if (!map) {
    return;
  }
}

void Context::replaceHeaderMapValue(HeaderMapType type, std::string_view key,
                                    std::string_view value) {
  auto map = getMap(type);
  if (!map) {
    return;
  }
}

uint32_t Context::getHeaderMapSize(HeaderMapType type) {
  auto map = getMap(type);
  if (!map) {
    return 0;
  }
  return 0;
}

// Body Buffer

std::string_view Context::getRequestBodyBufferBytes(uint32_t start, uint32_t length) {
  return "";
}

std::string_view Context::getResponseBodyBufferBytes(uint32_t start, uint32_t length) {
  return "";
}

// Async call via HTTP
uint32_t Context::httpCall(std::string_view cluster, const Pairs& request_headers,
                           std::string_view request_body, const Pairs& request_trailers,
                           int timeout_milliseconds) {
  return 0;
}

void Context::httpRespond(const Pairs& response_headers, std::string_view body,
                          const Pairs& response_trailers) {
  (void)response_headers;
  (void)body;
  (void)response_trailers;
}

WasmResult Context::setProperty(std::string_view key, std::string_view serialized_value) {
  return WasmResult::NotFound;
}

void Context::scriptLog(LogLevel level, std::string_view message) {
  switch (level) {
  case LogLevel::trace:
    TSDebug(WASM_DEBUG_TAG, "wasm trace log%s %*s", log_prefix_.c_str(), (int)message.size(), message.data());
    fprintf(stderr, "wasm trace log%s %*s\n", log_prefix_.c_str(), (int)message.size(), message.data());
    return;
  case LogLevel::debug:
    TSDebug(WASM_DEBUG_TAG, "wasm debug log%s: %*s", log_prefix_.c_str(), (int)message.size(), message.data());
    fprintf(stderr, "wasm debug log%s: %*s\n", log_prefix_.c_str(), (int)message.size(), message.data());
    return;
  case LogLevel::info:
    TSDebug(WASM_DEBUG_TAG, "wasm info log%s: %*s", log_prefix_.c_str(), (int)message.size(), message.data());
    fprintf(stderr, "wasm info log%s: %*s\n", log_prefix_.c_str(), (int)message.size(), message.data());
    return;
  case LogLevel::warn:
    TSDebug(WASM_DEBUG_TAG, "wasm warn log%s: %*s", log_prefix_.c_str(), (int)message.size(), message.data());
    fprintf(stderr, "wasm warn log%s: %*s\n", log_prefix_.c_str(), (int)message.size(), message.data());
    return;
  case LogLevel::error:
    TSDebug(WASM_DEBUG_TAG, "wasm error log%s: %*s", log_prefix_.c_str(), (int)message.size(), message.data());
    fprintf(stderr, "wasm error log%s: %*s\n", log_prefix_.c_str(), (int)message.size(), message.data());
    return;
  case LogLevel::critical:
    TSDebug(WASM_DEBUG_TAG, "wasm critical log%s: %*s", log_prefix_.c_str(), (int)message.size(), message.data());
    fprintf(stderr, "wasm critical log%s: %*s\n", log_prefix_.c_str(), (int)message.size(), message.data());
    return;
  default: // e.g. off
    return;
  }
}

// Connection
bool Context::isSsl() { return false; }

//
// Calls into the WASM code.
//
void Context::onStart(std::string_view root_id, std::string_view vm_configuration) {
  if (wasm_->onStart_) {
    auto root_id_addr = wasm_->copyString(root_id);
    auto config_addr = wasm_->copyString(vm_configuration);
    wasm_->onStart_(this, id_, root_id_addr, root_id.size(), config_addr, vm_configuration.size());
  }
}

bool Context::validateConfiguration(std::string_view configuration) {
  if (!wasm_->validateConfiguration_) {
    return true;
  }
  auto address = wasm_->copyString(configuration);
  return wasm_->validateConfiguration_(this, id_, address, configuration.size()).u64_ != 0;
}

bool Context::onConfigure(std::string_view configuration) {
  if (!wasm_->onConfigure_) {
    return true;
  }
  auto address = wasm_->copyString(configuration);
  return wasm_->onConfigure_(this, id_, address, configuration.size()).u64_ != 0;
}

void Context::onCreate() {
  if (wasm_->onCreate_) {
    wasm_->onCreate_(this, id_, root_context_ ? root_context_->id_ : 0);
  }
}

FilterHeadersStatus Context::onRequestHeaders() {
  if (!wasm_->onRequestHeaders_) {
    return FilterHeadersStatus::Continue;
  }
  if (wasm_->onRequestHeaders_(this, id_).u64_ == 0) {
    return FilterHeadersStatus::Continue;
  }
  return FilterHeadersStatus::StopIteration;
}

FilterDataStatus Context::onRequestBody(int body_buffer_length, bool end_of_stream) {
  if (!wasm_->onRequestBody_) {
    return FilterDataStatus::Continue;
  }
  switch (wasm_->onRequestBody_(this, id_, static_cast<uint32_t>(body_buffer_length),
                               static_cast<uint32_t>(end_of_stream))
              .u64_) {
  case 0:
    return FilterDataStatus::Continue;
  case 1:
    return FilterDataStatus::StopIterationAndBuffer;
  case 2:
    return FilterDataStatus::StopIterationAndWatermark;
  default:
    return FilterDataStatus::StopIterationNoBuffer;
  }
}

FilterTrailersStatus Context::onRequestTrailers() {
  if (!wasm_->onRequestTrailers_) {
    return FilterTrailersStatus::Continue;
  }
  if (wasm_->onRequestTrailers_(this, id_).u64_ == 0) {
    return FilterTrailersStatus::Continue;
  }
  return FilterTrailersStatus::StopIteration;
}

FilterMetadataStatus Context::onRequestMetadata() {
  if (!wasm_->onRequestMetadata_) {
    return FilterMetadataStatus::Continue;
  }
  if (wasm_->onRequestMetadata_(this, id_).u64_ == 0) {
    return FilterMetadataStatus::Continue;
  }
  return FilterMetadataStatus::Continue; // This is currently the only return code.
}

FilterHeadersStatus Context::onResponseHeaders() {
  if (!wasm_->onResponseHeaders_) {
    return FilterHeadersStatus::Continue;
  }
  if (wasm_->onResponseHeaders_(this, id_).u64_ == 0) {
    return FilterHeadersStatus::Continue;
  }
  return FilterHeadersStatus::StopIteration;
}

FilterDataStatus Context::onResponseBody(int body_buffer_length, bool end_of_stream) {
  if (!wasm_->onResponseBody_) {
    return FilterDataStatus::Continue;
  }
  switch (wasm_
              ->onResponseBody_(this, id_, static_cast<uint32_t>(body_buffer_length),
                                static_cast<uint32_t>(end_of_stream))
              .u64_) {
  case 0:
    return FilterDataStatus::Continue;
  case 1:
    return FilterDataStatus::StopIterationAndBuffer;
  case 2:
    return FilterDataStatus::StopIterationAndWatermark;
  default:
    return FilterDataStatus::StopIterationNoBuffer;
  }
}

FilterTrailersStatus Context::onResponseTrailers() {
  if (!wasm_->onResponseTrailers_) {
    return FilterTrailersStatus::Continue;
  }
  if (wasm_->onResponseTrailers_(this, id_).u64_ == 0) {
    return FilterTrailersStatus::Continue;
  }
  return FilterTrailersStatus::StopIteration;
}

FilterMetadataStatus Context::onResponseMetadata() {
  if (!wasm_->onResponseMetadata_) {
    return FilterMetadataStatus::Continue;
  }
  if (wasm_->onResponseMetadata_(this, id_).u64_ == 0) {
    return FilterMetadataStatus::Continue;
  }
  return FilterMetadataStatus::Continue; // This is currently the only return code.
}

WasmResult Context::continueRequest() {
  TSHttpTxnReenable(txnp_, TS_EVENT_HTTP_CONTINUE);
  return WasmResult::Ok;
}

WasmResult Context::continueResponse() {
  TSHttpTxnReenable(txnp_, TS_EVENT_HTTP_CONTINUE);
  return WasmResult::Ok;
}

void Context::onHttpCallResponse(uint32_t token, const Pairs& response_headers,
                                 std::string_view response_body, const Pairs& response_trailers) {
  if (!wasm_->onHttpCallResponse_) {
    return;
  }
  uint64_t headers_ptr, headers_size, trailers_ptr, trailers_size;
  exportPairs(this, response_headers, &headers_ptr, &headers_size);
  exportPairs(this, response_trailers, &trailers_ptr, &trailers_size);
  auto body_ptr = wasm_->copyString(response_body);
  auto body_size = response_body.size();
  wasm_->onHttpCallResponse_(this, id_, token, headers_ptr, headers_size, body_ptr, body_size,
                             trailers_ptr, trailers_size);
}

void Context::onQueueReady(uint32_t token) {
  if (wasm_->onQueueReady_) {
    wasm_->onQueueReady_(this, id_, token);
  }
}

WasmResult Context::defineMetric(MetricType type, std::string_view name, uint32_t* metric_id_ptr) {
  return WasmResult::BadArgument;
}

WasmResult Context::incrementMetric(uint32_t metric_id, int64_t offset) {
  return WasmResult::BadArgument;
}

WasmResult Context::recordMetric(uint32_t metric_id, uint64_t value) {
  return WasmResult::NotFound;
}

WasmResult Context::getMetric(uint32_t metric_id, uint64_t* result_uint64_ptr) {
  return WasmResult::NotFound;
}

Wasm::Wasm(std::string_view vm, std::string_view id, std::string_view vm_configuration)
    : vm_configuration_(vm_configuration) {
  wasm_vm_ = createWasmVm(vm);
  mutex_ = TSMutexCreate();
  id_ = std::string(id);
}

std::string Context::makeLogPrefix() const {
  std::string id;
  if (!wasm()->id().empty()) {
    id = id + " " + std::string(wasm()->id());
  }
  if (!root_id().empty()) {
    id = id + " " + std::string(root_id());
  }
  return id;
}

void Wasm::registerCallbacks() {
#define _REGISTER_ABI(_fn, _abi)                                                                   \
  wasm_vm_->registerCallback(                                                                      \
      "envoy", #_fn, &_fn##_abi##Handler,                                                          \
      &ConvertFunctionWordToUint32<decltype(_fn##_abi##Handler),                                   \
                                   _fn##_abi##Handler>::convertFunctionWordToUint32)
#define _REGISTER(_fn) _REGISTER_ABI(_fn, )

  if (is_emscripten_) {
    if (emscripten_abi_major_version_ > 0 || emscripten_abi_minor_version_ > 1) {
      // abi 0.2 - abortOnCannotGrowMemory() changed signature to (param i32) (result i32).
      _REGISTER_ABI(abortOnCannotGrowMemory, Abi02);
    } else {
      _REGISTER_ABI(abortOnCannotGrowMemory, Abi00);
    }

    _REGISTER(_emscripten_memcpy_big);
    _REGISTER(_emscripten_get_heap_size);
    _REGISTER(_emscripten_resize_heap);
    _REGISTER(abort);
    _REGISTER(_abort);
    _REGISTER(_llvm_trap);
    _REGISTER(___assert_fail);
    _REGISTER(___cxa_throw);
    _REGISTER(___cxa_pure_virtual);
    _REGISTER(___cxa_allocate_exception);
    _REGISTER(___cxa_uncaught_exception);
    _REGISTER(___cxa_uncaught_exceptions);
    _REGISTER(___call_main);
    _REGISTER(___clock_gettime);
    _REGISTER(___lock);
    _REGISTER(___unlock);
    _REGISTER(___syscall6);
    _REGISTER(___syscall54);
    _REGISTER(___syscall140);
    _REGISTER(___syscall146);
    _REGISTER(___wasi_fd_write);
    _REGISTER(___setErrNo);
    _REGISTER(_pthread_equal);
    _REGISTER(_pthread_mutex_destroy);
    _REGISTER(_pthread_cond_wait);
    _REGISTER(_pthread_getspecific);
    _REGISTER(_pthread_key_create);
    _REGISTER(_pthread_once);
    _REGISTER(_pthread_setspecific);
    _REGISTER(setTempRet0);
    wasm_vm_->makeModule("global.Math");
    wasm_vm_->registerCallback("global.Math", "log", globalMathLogHandler, &globalMathLogHandler);
  }
#undef _REGISTER
#undef _REGISTER_ABI

  // Calls with the "_proxy_" prefix.
#define _REGISTER_PROXY(_fn)                                                                       \
  wasm_vm_->registerCallback(                                                                      \
      "envoy", "_proxy_" #_fn, &_fn##Handler,                                                      \
      &ConvertFunctionWordToUint32<decltype(_fn##Handler),                                         \
                                   _fn##Handler>::convertFunctionWordToUint32);
  _REGISTER_PROXY(log);

  _REGISTER_PROXY(setProperty);
  _REGISTER_PROXY(getProperty);

  _REGISTER_PROXY(continueRequest);
  _REGISTER_PROXY(continueResponse);
  _REGISTER_PROXY(sendLocalResponse);
  _REGISTER_PROXY(clearRouteCache);

  _REGISTER_PROXY(getSharedData);
  _REGISTER_PROXY(setSharedData);

  _REGISTER_PROXY(registerSharedQueue);
  _REGISTER_PROXY(resolveSharedQueue);
  _REGISTER_PROXY(dequeueSharedQueue);
  _REGISTER_PROXY(enqueueSharedQueue);

  _REGISTER_PROXY(getHeaderMapValue);
  _REGISTER_PROXY(addHeaderMapValue);
  _REGISTER_PROXY(replaceHeaderMapValue);
  _REGISTER_PROXY(removeHeaderMapValue);
  _REGISTER_PROXY(getHeaderMapPairs);
  _REGISTER_PROXY(setHeaderMapPairs);
  _REGISTER_PROXY(getHeaderMapSize);

  _REGISTER_PROXY(getRequestBodyBufferBytes);
  _REGISTER_PROXY(getResponseBodyBufferBytes);

  _REGISTER_PROXY(httpCall);

  _REGISTER_PROXY(setTickPeriodMilliseconds);
  _REGISTER_PROXY(getCurrentTimeNanoseconds);

  _REGISTER_PROXY(defineMetric);
  _REGISTER_PROXY(incrementMetric);
  _REGISTER_PROXY(recordMetric);
  _REGISTER_PROXY(getMetric);

  _REGISTER_PROXY(setEffectiveContext);
#undef _REGISTER_PROXY
}

void Wasm::establishEnvironment() {
  if (is_emscripten_) {
    wasm_vm_->setMemoryLayout(emscripten_stack_base_, emscripten_dynamic_base_,
                              emscripten_dynamictop_ptr_);

    global_table_base_ = wasm_vm_->makeGlobal("env", "__table_base", Word(0));
    global_dynamictop_ =
        wasm_vm_->makeGlobal("env", "DYNAMICTOP_PTR", Word(emscripten_dynamictop_ptr_));

    wasm_vm_->makeModule("global");
    global_NaN_ = wasm_vm_->makeGlobal("global", "NaN", std::nan("0"));
    global_Infinity_ =
        wasm_vm_->makeGlobal("global", "Infinity", std::numeric_limits<double>::infinity());
  }
}

void Wasm::getFunctions() {
#define _GET(_fn) wasm_vm_->getFunction("_" #_fn, &_fn##_);
  _GET(malloc);
  _GET(free);
  _GET(__errno_location);
#undef _GET

#define _GET_PROXY(_fn) wasm_vm_->getFunction("_proxy_" #_fn, &_fn##_);
  _GET_PROXY(validateConfiguration);
  _GET_PROXY(onStart);
  _GET_PROXY(onConfigure);
  _GET_PROXY(onTick);

  _GET_PROXY(onCreate);
  _GET_PROXY(onRequestHeaders);
  _GET_PROXY(onRequestBody);
  _GET_PROXY(onRequestTrailers);
  _GET_PROXY(onRequestMetadata);
  _GET_PROXY(onResponseHeaders);
  _GET_PROXY(onResponseBody);
  _GET_PROXY(onResponseTrailers);
  _GET_PROXY(onResponseMetadata);
  _GET_PROXY(onHttpCallResponse);
  _GET_PROXY(onGrpcReceive);
  _GET_PROXY(onGrpcClose);
  _GET_PROXY(onGrpcCreateInitialMetadata);
  _GET_PROXY(onGrpcReceiveInitialMetadata);
  _GET_PROXY(onGrpcReceiveTrailingMetadata);
  _GET_PROXY(onQueueReady);
  _GET_PROXY(onDone);
  _GET_PROXY(onLog);
  _GET_PROXY(onDelete);
#undef _GET_PROXY

  if (!malloc_ || !free_) {
    throw WasmException("WASM missing malloc/free");
  }
}

Wasm::Wasm(const Wasm& wasm) : std::enable_shared_from_this<Wasm>(wasm), id_(wasm.id_) {
  wasm_vm_ = wasm.wasmVm()->clone();
  mutex_ = TSMutexCreate();
  vm_context_ = std::make_shared<Context>(this);
  getFunctions();
}

bool Wasm::initialize(const std::string& code, std::string_view name, bool allow_precompiled) {
  if (!wasm_vm_) {
    return false;
  }
  auto ok = wasm_vm_->load(code, allow_precompiled);
  if (!ok) {
    return false;
  }
  auto metadata = wasm_vm_->getUserSection("emscripten_metadata");
  if (!metadata.empty()) {
    // See https://github.com/emscripten-core/emscripten/blob/incoming/tools/shared.py#L3059
    is_emscripten_ = true;
    auto start = reinterpret_cast<const uint8_t*>(metadata.data());
    auto end = reinterpret_cast<const uint8_t*>(metadata.data() + metadata.size());
    start = decodeVarint(start, end, &emscripten_metadata_major_version_);
    start = decodeVarint(start, end, &emscripten_metadata_minor_version_);
    start = decodeVarint(start, end, &emscripten_abi_major_version_);
    start = decodeVarint(start, end, &emscripten_abi_minor_version_);
    if (emscripten_metadata_major_version_ > 0 || emscripten_metadata_minor_version_ > 1) {
      // metadata 0.2 - added: wasm_backend.
      uint32_t temp;
      start = decodeVarint(start, end, &temp);
    }
    start = decodeVarint(start, end, &emscripten_memory_size_);
    start = decodeVarint(start, end, &emscripten_table_size_);
    if (emscripten_metadata_major_version_ > 0 || emscripten_metadata_minor_version_ > 0) {
      // metadata 0.1 - added: global_base, dynamic_base, dynamictop_ptr and tempdouble_ptr.
      start = decodeVarint(start, end, &emscripten_global_base_);
      start = decodeVarint(start, end, &emscripten_dynamic_base_);
      start = decodeVarint(start, end, &emscripten_dynamictop_ptr_);
      decodeVarint(start, end, &emscripten_tempdouble_ptr_);
      if (emscripten_metadata_major_version_ > 0 || emscripten_metadata_minor_version_ > 2) {
        // metadata 0.3 - added: standalone_wasm.
        uint32_t temp;
        start = decodeVarint(start, end, &temp);
      }
    } else {
      // Workaround for Emscripten versions without heap (dynamic) base in metadata.
      emscripten_stack_base_ = 64 * 64 * 1024;      // 4MB
      emscripten_dynamic_base_ = 128 * 64 * 1024;   // 8MB
      emscripten_dynamictop_ptr_ = 128 * 64 * 1024; // 8MB
    }
  }
  registerCallbacks();
  establishEnvironment();
  wasm_vm_->link(name, is_emscripten_);
  vm_context_ = std::make_shared<Context>(this);
  getFunctions();
  wasm_vm_->start(vm_context_.get());
  if (is_emscripten_) {
    if (!std::isnan(global_NaN_->get())) {
      return false;
    }
    if (!std::isinf(global_Infinity_->get())) {
      return false;
    }
  }
  code_ = code;
  allow_precompiled_ = allow_precompiled;
  return true;
}

bool Wasm::configure(Context* root_context, std::string_view configuration) {
  if (!onConfigure_) {
    return true;
  }
  auto address = copyString(configuration);
  return onConfigure_(root_context, root_context->id(), address, configuration.size()).u64_ != 0;
}

Context* Wasm::start(std::string_view root_id, std::string_view vm_configuration) {
  auto it = root_contexts_.find(std::string(root_id));
  if (it != root_contexts_.end()) {
    it->second->onStart(root_id, vm_configuration);
    return it->second.get();
  }
  auto context = std::make_unique<Context>(this, root_id);
  auto context_ptr = context.get();
  root_contexts_[std::string(root_id)] = std::move(context);
  context_ptr->onStart(root_id, vm_configuration);
  return context_ptr;
};

void Wasm::startForTesting(std::unique_ptr<Context> context) {
  auto context_ptr = context.get();
  if (!context->wasm_) {
    // Initialization was delayed till the Wasm object was created.
    context->wasm_ = this;
    context->id_ = allocContextId();
    context->makeLogPrefix();
    contexts_[context->id_] = context.get();
  }
  root_contexts_[""] = std::move(context);
  context_ptr->onStart("", "");
}

void Wasm::setErrno(int32_t err) {
  if (!__errno_location_) {
    return;
  }
  Word location = __errno_location_(vmContext());
  setDatatype(location.u64_, err);
}

// ATS time is in ns
void Wasm::setTickPeriod(uint32_t context_id, uint64_t new_tick_period) {
  (void)context_id;
  (void)new_tick_period;
}

void Wasm::tickHandler(uint32_t root_context_id) {
  if (onTick_) {
    onTick_(getContext(root_context_id), root_context_id);
  }
}

uint32_t Wasm::allocContextId() {
  while (true) {
    auto id = next_context_id_++;
    // Prevent reuse.
    if (contexts_.find(id) == contexts_.end()) {
      return id;
    }
  }
}

void Wasm::queueReady(uint32_t root_context_id, uint32_t token) {
  auto it = contexts_.find(root_context_id);
  if (it == contexts_.end() || !it->second->isRootContext()) {
    return;
  }
  it->second->onQueueReady(token);
}

static int http_event_handler(TSCont contp, TSEvent event, void *data)
{
  int result = -1;
  auto context = (Context*)TSContDataGet(contp);
  TSHttpTxn txnp = context->txnp();

  TSMutexUnlock(context->wasm()->mutex());

  switch (event) {

  case TS_EVENT_HTTP_TXN_START:
    break;

  case TS_EVENT_HTTP_READ_REQUEST_HDR:
    result = context->onRequestHeaders() == FilterHeadersStatus::Continue ? 0 : 1;
    break;

  case TS_EVENT_HTTP_POST_REMAP:
    break;

  case TS_EVENT_HTTP_CACHE_LOOKUP_COMPLETE:
    break;

  case TS_EVENT_HTTP_SEND_REQUEST_HDR:
    break;

  case TS_EVENT_HTTP_READ_RESPONSE_HDR:
    result = context->onResponseHeaders() == FilterHeadersStatus::Continue ? 0 : 1;
    break;

  case TS_EVENT_HTTP_SEND_RESPONSE_HDR:
    break;

  case TS_EVENT_HTTP_PRE_REMAP:
    break;

  case TS_EVENT_HTTP_OS_DNS:
    break;

  case TS_EVENT_HTTP_READ_CACHE_HDR:
    break;

  case TS_EVENT_HTTP_TXN_CLOSE:
    context->onDone();
    context->onDestroy();
    TSMutexUnlock(context->wasm()->mutex());
    delete context;
    TSContDestroy(contp);
    return 0;

  default:
    break;
  }

  TSMutexUnlock(context->wasm()->mutex());

  if (result == 0) {
    TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
  } else if (result < 0) {
    TSHttpTxnReenable(txnp, TS_EVENT_HTTP_ERROR);
  } else {
    // wait for async operation
  }
  return 0;
}

TSCont Context::initialize(TSCont global_contp, TSHttpTxn txnp) {
  global_contp_ = global_contp;
  txnp_ = txnp;
  txn_contp_ = TSContCreate(http_event_handler, nullptr);
  //TSHttpTxnHookAdd(txnp, TS_HTTP_CACHE_LOOKUP_COMPLETE_HOOK, txn_contp_);
  TSHttpTxnHookAdd(txnp, TS_HTTP_READ_REQUEST_HDR_HOOK, txn_contp_);
  //TSHttpTxnHookAdd(txnp, TS_HTTP_PRE_REMAP_HOOK, txn_contp_);
  //TSHttpTxnHookAdd(txnp, TS_HTTP_POST_REMAP_HOOK, txn_contp_);
  //TSHttpTxnHookAdd(txnp, TS_HTTP_OS_DNS_HOOK, txn_contp_);
  //TSHttpTxnHookAdd(txnp, TS_HTTP_REQUEST_TRANSFORM_HOOK, txn_contp_);
  //TSHttpTxnHookAdd(txnp, TS_HTTP_SEND_REQUEST_HDR_HOOK, txn_contp_);
  //TSHttpTxnHookAdd(txnp, TS_HTTP_READ_CACHE_HDR_HOOK, txn_contp_);
  TSHttpTxnHookAdd(txnp, TS_HTTP_READ_RESPONSE_HDR_HOOK, txn_contp_);
  //TSHttpTxnHookAdd(txnp, TS_HTTP_SEND_RESPONSE_HDR_HOOK, txn_contp_);
  //TSHttpTxnHookAdd(txnp, TS_HTTP_RESPONSE_TRANSFORM_HOOK, txn_contp_);
  TSHttpTxnHookAdd(txnp, TS_HTTP_TXN_CLOSE_HOOK, txn_contp_);
  return txn_contp_;
}


void Context::onDestroy() {
  if (destroyed_) {
    return;
  }
  destroyed_ = true;
  onDone();
}

void Context::onDone() {
  if (wasm_->onDone_) {
    wasm_->onDone_(this, id_);
  }
}

void Context::onLog() {
  if (wasm_->onLog_) {
    wasm_->onLog_(this, id_);
  }
}

void Context::onDelete() {
  if (wasm_->onDelete_) {
    wasm_->onDelete_(this, id_);
  }
}

void Context::onHttpCallSuccess(uint32_t token) {
  onHttpCallResponse(token, {}, "", {});
  http_request_.erase(token);
}

void Context::onHttpCallFailure(uint32_t token) {
  onHttpCallResponse(token, {}, "", {});
  http_request_.erase(token);
}

void AsyncClientHandler::onSuccess() {
  context->onHttpCallSuccess(token);
}

void AsyncClientHandler::onFailure() {
  context->onHttpCallFailure(token);
}

static std::shared_ptr<Wasm> createWasmInternal(
    std::string_view vm_id, std::string_view vm, const std::string& code, std::string_view vm_configuration,
    std::string_view root_id, // e.g. filter instance id
    std::unique_ptr<Context> root_context_for_testing) {
  auto wasm = std::make_shared<Wasm>(vm, vm_id, vm_configuration);
  if (code.empty()) {
    TSError("[wasm] unable to get code");
    return nullptr;
  }
  if (!wasm->initialize(code, vm_id, true)) {
    TSError("[wasm] unable to initalize vm");
    return nullptr;
  }
  if (!root_context_for_testing) {
    wasm->start(root_id, vm_configuration);
  } else {
    wasm->startForTesting(std::move(root_context_for_testing));
  }
  return wasm;
}

std::shared_ptr<Wasm> createWasm(
    std::string_view vm_id, std::string_view vm, const std::string& code, std::string_view vm_configuration,
                                 std::string_view root_id) {
  return createWasmInternal(vm_id, vm, code, vm_configuration, root_id, nullptr);
}

std::shared_ptr<Wasm> createThreadLocalWasm(Wasm& base_wasm, std::string_view root_id,
                                            std::string_view configuration) {
  std::shared_ptr<Wasm> wasm;
  Context* root_context;
  if (base_wasm.wasmVm()->cloneable()) {
    wasm = std::make_shared<Wasm>(base_wasm);
    root_context = wasm->start(root_id, base_wasm.vm_configuration());
  } else {
    wasm = std::make_shared<Wasm>(base_wasm.wasmVm()->vm(), base_wasm.id(), base_wasm.vm_configuration());
    if (!wasm->initialize(base_wasm.code(), base_wasm.id(), base_wasm.allow_precompiled())) {
      return nullptr;
    }
    root_context = wasm->start(root_id, base_wasm.vm_configuration());
  }
  if (!wasm->configure(root_context, configuration)) {
    return nullptr;
  }
  if (!wasm->id().empty()) {
    local_wasms[wasm->id()] = wasm;
  }
  return wasm;
}

std::shared_ptr<Wasm> getThreadLocalWasm(std::string_view vm_id, std::string_view id,
                                         std::string_view configuration) {
  auto it = local_wasms.find(std::string(vm_id));
  if (it == local_wasms.end()) {
    return nullptr;
  }
  auto wasm = it->second;
  auto root_context = wasm->start(id, wasm->vm_configuration());
  if (!wasm->configure(root_context, configuration)) {
    return nullptr;
  }
  return wasm;
}

std::shared_ptr<Wasm> getThreadLocalWasmOrNull(std::string_view id) {
  auto it = local_wasms.find(std::string(id));
  if (it == local_wasms.end()) {
    return nullptr;
  }
  return it->second;
}

} // namespace Wasm
