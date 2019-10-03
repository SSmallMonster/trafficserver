#pragma once

#include <string.h>

#include <map>
#include <memory>
#include <vector>

#include "ts/ts.h"

#include "wasm_vm.h"

namespace Wasm
{
#include "proxy_wasm_enums.h"
#include "proxy_wasm_result.h"
#include "proxy_wasm_metadata.h"

class Context;
class Wasm;
class WasmVm;

struct HeaderMap {
  TSMBuffer bufp{nullptr};
  TSMLoc hdr_loc{nullptr};

  int size();
};

using Pairs                 = std::vector<std::pair<std::string_view, std::string_view>>;
using PairsWithStringValues = std::vector<std::pair<std::string_view, std::string>>;

enum class StreamType : int32_t { Request = 0, Response = 1, MAX = 1 };

// Handlers for functions exported from envoy to wasm.
Word logHandler(void *raw_context, Word level, Word address, Word size);
Word getPropertyHandler(void *raw_context, Word path_ptr, Word path_size, Word value_ptr_ptr, Word value_size_ptr);
Word setPropertyHandler(void *raw_context, Word key_ptr, Word key_size, Word value_ptr, Word value_size);
Word continueRequestHandler(void *raw_context);
Word continueResponseHandler(void *raw_context);
Word sendLocalResponseHandler(void *raw_context, Word response_code, Word response_code_details_ptr,
                              Word response_code_details_size, Word body_ptr, Word body_size,
                              Word additional_response_header_pairs_ptr, Word additional_response_header_pairs_size);
Word clearRouteCacheHandler(void *raw_context);
Word getSharedDataHandler(void *raw_context, Word key_ptr, Word key_size, Word value_ptr_ptr, Word value_size_ptr, Word cas_ptr);
Word setSharedDataHandler(void *raw_context, Word key_ptr, Word key_size, Word value_ptr, Word value_size, Word cas);
Word registerSharedQueueHandler(void *raw_context, Word queue_name_ptr, Word queue_name_size, Word token_ptr);
Word resolveSharedQueueHandler(void *raw_context, Word vm_id_ptr, Word vm_id_size, Word queue_name_ptr, Word queue_name_size,
                               Word token_ptr);
Word dequeueSharedQueueHandler(void *raw_context, Word token, Word data_ptr_ptr, Word data_size_ptr);
Word enqueueSharedQueueHandler(void *raw_context, Word token, Word data_ptr, Word data_size);
Word addHeaderMapValueHandler(void *raw_context, Word type, Word key_ptr, Word key_size, Word value_ptr, Word value_size);
Word getHeaderMapValueHandler(void *raw_context, Word type, Word key_ptr, Word key_size, Word value_ptr_ptr, Word value_size_ptr);
Word replaceHeaderMapValueHandler(void *raw_context, Word type, Word key_ptr, Word key_size, Word value_ptr, Word value_size);
Word removeHeaderMapValueHandler(void *raw_context, Word type, Word key_ptr, Word key_size);
Word getHeaderMapPairsHandler(void *raw_context, Word type, Word ptr_ptr, Word size_ptr);
Word setHeaderMapPairsHandler(void *raw_context, Word type, Word ptr, Word size);
Word getHeaderMapSizeHandler(void *raw_context, Word type, Word result_ptr);
Word getRequestBodyBufferBytesHandler(void *raw_context, Word start, Word length, Word ptr_ptr, Word size_ptr);
Word getResponseBodyBufferBytesHandler(void *raw_context, Word start, Word length, Word ptr_ptr, Word size_ptr);
Word httpCallHandler(void *raw_context, Word uri_ptr, Word uri_size, Word header_pairs_ptr, Word header_pairs_size, Word body_ptr,
                     Word body_size, Word trailer_pairs_ptr, Word trailer_pairs_size, Word timeout_milliseconds);
Word defineMetricHandler(void *raw_context, Word metric_type, Word name_ptr, Word name_size, Word result_ptr);
Word incrementMetricHandler(void *raw_context, Word metric_id, int64_t offset);
Word recordMetricHandler(void *raw_context, Word metric_id, uint64_t value);
Word setTickPeriodMillisecondsHandler(void *raw_context, Word tick_period_milliseconds);
Word getCurrentTimeNanosecondsHandler(void *raw_context, Word result_uint64_ptr);

Word setEffectiveContextHandler(void *raw_context, Word context_id);

inline MetadataType
StreamType2MetadataType(StreamType type)
{
  return static_cast<MetadataType>(type);
}

struct AsyncClientHandler {
  void onSuccess();
  void onFailure();

  Context *context;
  uint32_t token;
};

// A context which will be the target of callbacks for a particular session
// e.g. a handler of a stream.
class Context : public std::enable_shared_from_this<Context>
{
public:
  Context();                                     // Testing.
  explicit Context(Wasm *wasm);                  // General Context.
  Context(Wasm *wasm, std::string_view root_id); // Root Context.
  Context(Wasm *wasm, uint32_t root_context_id); // Stream/Filter context.
  virtual ~Context();

  TSCont initialize(TSCont global_contp, TSHttpTxn txnp);

  Wasm *
  wasm() const
  {
    return wasm_;
  }
  WasmVm *wasmVm() const;
  uint32_t
  id() const
  {
    return id_;
  }
  std::string_view root_id() const;
  bool
  isVmContext()
  {
    return id_ == 0;
  }
  bool
  isRootContext()
  {
    return root_context_id_ == 0;
  }
  Context *
  root_context()
  {
    return root_context_;
  }
  TSHttpTxn
  txnp()
  {
    return txnp_;
  }

  //
  // VM level downcalls into the WASM code on Context(id == 0).
  //
  virtual bool validateConfiguration(std::string_view configuration);
  virtual void onStart(std::string_view root_id, std::string_view vm_configuration);
  virtual bool onConfigure(std::string_view configuration);

  //
  // Stream downcalls on Context(id > 0).
  //
  // General stream downcall on a new stream.
  virtual void onCreate();
  // HTTP Filter Stream Request Downcalls.
  virtual FilterHeadersStatus onRequestHeaders();
  virtual FilterDataStatus onRequestBody(int body_buffer_length, bool end_of_stream);
  virtual FilterTrailersStatus onRequestTrailers();
  virtual FilterMetadataStatus onRequestMetadata();
  // HTTP Filter Stream Response Downcalls.
  virtual FilterHeadersStatus onResponseHeaders();
  virtual FilterDataStatus onResponseBody(int body_buffer_length, bool end_of_stream);
  virtual FilterTrailersStatus onResponseTrailers();
  virtual FilterMetadataStatus onResponseMetadata();

  virtual WasmResult continueRequest();
  virtual WasmResult continueResponse();

  // Async Response Downcalls on any Context.
  virtual void onHttpCallResponse(uint32_t token, const Pairs &response_headers, std::string_view response_body,
                                  const Pairs &response_trailers);
  virtual void onQueueReady(uint32_t token);
  // General stream downcall when the stream has ended.
  virtual void onDone();
  // General stream downcall for logging. Occurs after onDone().
  virtual void onLog();
  // General stream downcall when no further stream calls will occur.
  virtual void onDelete();

  //
  // General Callbacks.
  //
  virtual void scriptLog(LogLevel level, std::string_view message);
  virtual WasmResult setTickPeriod(uint64_t tick_period);
  virtual uint64_t getCurrentTimeNanoseconds();

  // Note: This calls onDone() in WASM.
  virtual void onDestroy();

  //
  // HTTP Filter Callbacks
  //

  // State accessors
  virtual WasmResult getProperty(std::string_view path, std::string *result);
  virtual WasmResult setProperty(std::string_view key, std::string_view serialized_value);

  // Send Response
  virtual void
  sendLocalResponse(uint64_t response_code, std::string_view body_text, Pairs additional_headers)
  {
  }

  // Shared Data
  virtual WasmResult getSharedData(std::string_view key, std::pair<std::string, uint32_t /* cas */> *data);
  virtual WasmResult setSharedData(std::string_view key, std::string_view value, uint32_t cas);

  // Shared Queue
  virtual uint32_t registerSharedQueue(std::string_view queue_name);
  virtual WasmResult resolveSharedQueue(std::string_view vm_id, std::string_view queue_name, uint32_t *token);
  virtual WasmResult dequeueSharedQueue(uint32_t token, std::string *data);
  virtual WasmResult enqueueSharedQueue(uint32_t token, std::string_view value);

  // Header/Trailer/Metadata Maps
  virtual void addHeaderMapValue(HeaderMapType type, std::string_view key, std::string_view value);
  virtual std::string_view getHeaderMapValue(HeaderMapType type, std::string_view key);
  virtual Pairs getHeaderMapPairs(HeaderMapType type);
  virtual void setHeaderMapPairs(HeaderMapType type, const Pairs &pairs);

  virtual void removeHeaderMapValue(HeaderMapType type, std::string_view key);
  virtual void replaceHeaderMapValue(HeaderMapType type, std::string_view key, std::string_view value);

  virtual uint32_t getHeaderMapSize(HeaderMapType type);

  // Body Buffer
  virtual std::string_view getRequestBodyBufferBytes(uint32_t start, uint32_t length);
  virtual std::string_view getResponseBodyBufferBytes(uint32_t start, uint32_t length);

  // HTTP
  // Returns a token which will be used with the corresponding onHttpCallResponse.
  virtual uint32_t httpCall(std::string_view cluster, const Pairs &request_headers, std::string_view request_body,
                            const Pairs &request_trailers, int timeout_millisconds);
  virtual void httpRespond(const Pairs &response_headers, std::string_view body, const Pairs &response_trailers);

  // Stats/Metrics
  enum class MetricType : uint32_t {
    Counter   = 0,
    Gauge     = 1,
    Histogram = 2,
    Max       = 2,
  };
  virtual WasmResult defineMetric(MetricType type, std::string_view name, uint32_t *metric_id_ptr);
  virtual WasmResult incrementMetric(uint32_t metric_id, int64_t offset);
  virtual WasmResult recordMetric(uint32_t metric_id, uint64_t value);
  virtual WasmResult getMetric(uint32_t metric_id, uint64_t *value_ptr);

  // Connection
  virtual bool isSsl();

protected:
  friend class Wasm;
  friend struct AsyncClientHandler;

  void onHttpCallSuccess(uint32_t token);
  void onHttpCallFailure(uint32_t token);

  HeaderMap getHeaderMap(HeaderMapType type);

  std::string makeLogPrefix() const;

  Wasm *wasm_;
  uint32_t id_;
  uint32_t root_context_id_;       // 0 for roots and the general context.
  Context *root_context_{nullptr}; // set in all contexts.
  const std::string root_id_;      // set only in roots.
  std::string log_prefix_;
  bool destroyed_ = false;

  TSCont global_contp_{nullptr};
  TSHttpTxn txnp_{nullptr};
  TSCont txn_contp_{nullptr};
  TSMutex ts_mutex_{nullptr};

  uint32_t next_http_call_token_ = 1;

  // MB: must be a node-type map as we take persistent references to the entries.
  std::map<uint32_t, AsyncClientHandler> http_request_;
};

// Wasm execution instance. Manages the Envoy side of the Wasm interface.
class Wasm : public std::enable_shared_from_this<Wasm>
{
public:
  Wasm(std::string_view vm, std::string_view id, std::string_view vm_configuration);
  Wasm(const Wasm &other);
  ~Wasm()
  {
    if (mutex_)
      TSMutexDestroy(mutex_);
  }

  TSMutex
  mutex()
  {
    return mutex_;
  }

  bool initialize(const std::string &code, std::string_view name, bool allow_precompiled);
  bool configure(Context *root_context, std::string_view configuration);
  Context *start(std::string_view root_id,
                 std::string_view vm_configuration); // returns the root Context.

  const std::string &
  id() const
  {
    return id_;
  }
  WasmVm *
  wasmVm() const
  {
    return wasm_vm_.get();
  }
  Context *
  vmContext() const
  {
    return vm_context_.get();
  }
  Context *
  getRootContext(std::string_view root_id)
  {
    return root_contexts_[std::string(root_id)].get();
  }
  Context *
  getContext(uint32_t id)
  {
    auto it = contexts_.find(id);
    if (it != contexts_.end())
      return it->second;
    return nullptr;
  }

  void setTickPeriod(uint32_t root_context_id, uint64_t tick_period);
  void tickHandler(uint32_t root_context_id);
  void queueReady(uint32_t root_context_id, uint32_t token);

  uint32_t allocContextId();

  const std::string &
  code() const
  {
    return code_;
  }
  const std::string &
  vm_configuration() const
  {
    return vm_configuration_;
  }
  bool
  allow_precompiled() const
  {
    return allow_precompiled_;
  }
  void
  setInitialConfiguration(const std::string &vm_configuration)
  {
    vm_configuration_ = vm_configuration;
  }

  // Support functions.
  void *allocMemory(uint64_t size, uint64_t *address);
  bool freeMemory(void *pointer);
  void freeMemoryOffset(uint64_t address);
  // Allocate a null-terminated string in the VM and return the pointer to use as a call arguments.
  uint64_t copyString(std::string_view s);
  // Copy the data in 's' into the VM along with the pointer-size pair. Returns true on success.
  bool copyToPointerSize(std::string_view s, uint64_t ptr_ptr, uint64_t size_ptr);
  template <typename T> bool setDatatype(uint64_t ptr, const T &t);

  // For testing.
  void
  setContext(Context *context)
  {
    contexts_[context->id()] = context;
  }
  void startForTesting(std::unique_ptr<Context> root_context);

  bool
  getEmscriptenVersion(uint32_t *emscripten_metadata_major_version, uint32_t *emscripten_metadata_minor_version,
                       uint32_t *emscripten_abi_major_version, uint32_t *emscripten_abi_minor_version)
  {
    if (!is_emscripten_) {
      return false;
    }
    *emscripten_metadata_major_version = emscripten_metadata_major_version_;
    *emscripten_metadata_minor_version = emscripten_metadata_minor_version_;
    *emscripten_abi_major_version      = emscripten_abi_major_version_;
    *emscripten_abi_minor_version      = emscripten_abi_minor_version_;
    return true;
  }

  void setErrno(int32_t err);

private:
  friend class Context;
  // These are the same as the values of the Context::MetricType enum, here separately for
  // convenience.
  static const uint32_t kMetricTypeCounter   = 0x0;
  static const uint32_t kMetricTypeGauge     = 0x1;
  static const uint32_t kMetricTypeHistogram = 0x2;
  static const uint32_t kMetricTypeMask      = 0x3;
  static const uint32_t kMetricIdIncrement   = 0x4;
  static void
  StaticAsserts()
  {
    static_assert(static_cast<uint32_t>(Context::MetricType::Counter) == kMetricTypeCounter, "");
    static_assert(static_cast<uint32_t>(Context::MetricType::Gauge) == kMetricTypeGauge, "");
    static_assert(static_cast<uint32_t>(Context::MetricType::Histogram) == kMetricTypeHistogram, "");
  }

  bool
  isCounterMetricId(uint32_t metric_id)
  {
    return (metric_id & kMetricTypeMask) == kMetricTypeCounter;
  }
  bool
  isGaugeMetricId(uint32_t metric_id)
  {
    return (metric_id & kMetricTypeMask) == kMetricTypeGauge;
  }
  bool
  isHistogramMetricId(uint32_t metric_id)
  {
    return (metric_id & kMetricTypeMask) == kMetricTypeHistogram;
  }
  uint32_t
  nextCounterMetricId()
  {
    return next_counter_metric_id_ += kMetricIdIncrement;
  }
  uint32_t
  nextGaugeMetricId()
  {
    return next_gauge_metric_id_ += kMetricIdIncrement;
  }
  uint32_t
  nextHistogramMetricId()
  {
    return next_histogram_metric_id_ += kMetricIdIncrement;
  }

  void registerCallbacks();    // Register functions called out from WASM.
  void establishEnvironment(); // Language specific environments.
  void getFunctions();         // Get functions call into WASM.

  std::string id_;
  uint32_t next_context_id_ = 1; // 0 is reserved for the VM context.
  std::unique_ptr<WasmVm> wasm_vm_;
  std::shared_ptr<Context> vm_context_; // Context unrelated to any specific root or stream
                                        // (e.g. for global constructors).
  std::unordered_map<std::string, std::unique_ptr<Context>> root_contexts_;
  std::unordered_map<uint32_t, Context *> contexts_;   // Contains all contexts.
  std::unordered_map<uint32_t, uint64_t> tick_period_; // per root_id.
  std::unordered_map<uint32_t, void *> timer_;         // per root_id.

  WasmCallWord<1> malloc_;
  WasmCallVoid<1> free_;
  WasmCallWord<0> __errno_location_;

  // Calls into the VM.
  WasmCallWord<3> validateConfiguration_;
  WasmCallVoid<5> onStart_;
  WasmCallWord<3> onConfigure_;
  WasmCallVoid<1> onTick_;

  WasmCallVoid<2> onCreate_;

  WasmCallWord<1> onRequestHeaders_;
  WasmCallWord<3> onRequestBody_;
  WasmCallWord<1> onRequestTrailers_;
  WasmCallWord<1> onRequestMetadata_;

  WasmCallWord<1> onResponseHeaders_;
  WasmCallWord<3> onResponseBody_;
  WasmCallWord<1> onResponseTrailers_;
  WasmCallWord<1> onResponseMetadata_;

  WasmCallVoid<8> onHttpCallResponse_;

  WasmCallVoid<4> onGrpcReceive_;
  WasmCallVoid<5> onGrpcClose_;
  WasmCallVoid<2> onGrpcCreateInitialMetadata_;
  WasmCallVoid<2> onGrpcReceiveInitialMetadata_;
  WasmCallVoid<2> onGrpcReceiveTrailingMetadata_;

  WasmCallVoid<2> onQueueReady_;

  WasmCallVoid<1> onDone_;
  WasmCallVoid<1> onLog_;
  WasmCallVoid<1> onDelete_;

  // Used by the base_wasm to enable non-clonable thread local Wasm(s) to be constructed.
  std::string code_;
  std::string vm_configuration_;
  bool allow_precompiled_ = false;
  TSMutex mutex_{nullptr};

  bool is_emscripten_                         = false;
  uint32_t emscripten_metadata_major_version_ = 0;
  uint32_t emscripten_metadata_minor_version_ = 0;
  uint32_t emscripten_abi_major_version_      = 0;
  uint32_t emscripten_abi_minor_version_      = 0;
  uint32_t emscripten_memory_size_            = 0;
  uint32_t emscripten_table_size_             = 0;
  uint32_t emscripten_global_base_            = 0;
  uint32_t emscripten_stack_base_             = 0;
  uint32_t emscripten_dynamic_base_           = 0;
  uint32_t emscripten_dynamictop_ptr_         = 0;
  uint32_t emscripten_tempdouble_ptr_         = 0;

  std::unique_ptr<Global<Word>> global_table_base_;
  std::unique_ptr<Global<Word>> global_dynamictop_;
  std::unique_ptr<Global<double>> global_NaN_;
  std::unique_ptr<Global<double>> global_Infinity_;

  // Stats/Metrics
  uint32_t next_counter_metric_id_   = kMetricTypeCounter;
  uint32_t next_gauge_metric_id_     = kMetricTypeGauge;
  uint32_t next_histogram_metric_id_ = kMetricTypeHistogram;
  std::unordered_map<uint32_t, void *> counters_;
  std::unordered_map<uint32_t, void *> gauges_;
  std::unordered_map<uint32_t, void *> histograms_;
};

struct WasmInstanceConfig {
  std::string wasm_filename;
  std::shared_ptr<Wasm> wasm;
};

inline WasmVm *
Context::wasmVm() const
{
  return wasm_->wasmVm();
}

// Create a high level Wasm VM with API support. Note: 'id' may be empty if this VM will not
// be shared by APIs (e.g. HTTP Filter + AccessLog).
std::shared_ptr<Wasm> createWasm(std::string_view vm_id, std::string_view vm, const std::string &code,
                                 std::string_view vm_configuration, std::string_view root_id);

// Create a ThreadLocal VM from an existing VM (e.g. from createWasm() above).
std::shared_ptr<Wasm> createThreadLocalWasm(Wasm &base_wasm, std::string_view root_id, std::string_view configuration);

// Get an existing ThreadLocal VM matching 'vm_id'.
std::shared_ptr<Wasm> getThreadLocalWasm(std::string_view vm_id, std::string_view root_id, std::string_view configuration);
std::shared_ptr<Wasm> getThreadLocalWasmOrNull(std::string_view vm_id);

uint32_t resolveQueueForTest(std::string_view vm_id, std::string_view queue_name);

inline Context::Context() : wasm_(nullptr), id_(0), root_context_id_(0), root_context_(this), root_id_("") {}

inline Context::Context(Wasm *wasm)
  : wasm_(wasm), id_(0), root_context_id_(0), root_context_(this), root_id_(""), log_prefix_(makeLogPrefix())
{
  wasm_->contexts_[id_] = this;
}

inline Context::Context(Wasm *wasm, uint32_t root_context_id)
  : wasm_(wasm), id_(wasm->allocContextId()), root_context_id_(root_context_id), root_id_(""), log_prefix_(makeLogPrefix())
{
  wasm_->contexts_[id_] = this;
  root_context_         = wasm_->contexts_[root_context_id_];
}

inline Context::Context(Wasm *wasm, std::string_view root_id)
  : wasm_(wasm),
    id_(wasm->allocContextId()),
    root_context_id_(0),
    root_context_(this),
    root_id_(root_id),
    log_prefix_(makeLogPrefix())
{
  wasm_->contexts_[id_] = this;
}

// Do not remove vm or root contexts which have the same lifetime as wasm_.
inline Context::~Context()
{
  if (root_context_id_)
    wasm_->contexts_.erase(id_);
}

inline std::string_view
Context::root_id() const
{
  if (root_context_id_) {
    return wasm_->getContext(root_context_id_)->root_id_;
  } else {
    return root_id_;
  }
}

inline void *
Wasm::allocMemory(uint64_t size, uint64_t *address)
{
  Word a = malloc_(vmContext(), size);
  if (!a.u64_) {
    throw WasmException("malloc_ returns nullptr (OOM)");
  }
  auto memory = wasm_vm_->getMemory(a.u64_, size);
  if (!memory) {
    throw WasmException("malloc_ returned illegal address");
  }
  *address = a.u64_;
  return const_cast<void *>(reinterpret_cast<const void *>(memory.value().data()));
}

inline void
Wasm::freeMemoryOffset(uint64_t address)
{
  free_(vmContext(), address);
}

inline bool
Wasm::freeMemory(void *pointer)
{
  uint64_t offset;
  if (!wasm_vm_->getMemoryOffset(pointer, &offset)) {
    return false;
  }
  freeMemoryOffset(offset);
  return true;
}

inline uint64_t
Wasm::copyString(std::string_view s)
{
  if (s.empty()) {
    return 0; // nullptr
  }
  uint64_t pointer;
  uint8_t *m = static_cast<uint8_t *>(allocMemory((s.size() + 1), &pointer));
  memcpy(m, s.data(), s.size());
  m[s.size()] = 0;
  return pointer;
}

inline bool
Wasm::copyToPointerSize(std::string_view s, uint64_t ptr_ptr, uint64_t size_ptr)
{
  uint64_t pointer = 0;
  uint64_t size    = s.size();
  void *p          = nullptr;
  if (size > 0) {
    p = allocMemory(size, &pointer);
    if (!p) {
      return false;
    }
    memcpy(p, s.data(), size);
  }
  if (!wasm_vm_->setWord(ptr_ptr, Word(pointer))) {
    return false;
  }
  if (!wasm_vm_->setWord(size_ptr, Word(size))) {
    return false;
  }
  return true;
}

template <typename T>
inline bool
Wasm::setDatatype(uint64_t ptr, const T &t)
{
  return wasm_vm_->setMemory(ptr, sizeof(T), &t);
}

} // namespace Wasm
