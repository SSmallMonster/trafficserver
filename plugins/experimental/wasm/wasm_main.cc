/*
  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

#include "wasm.h"

#include <getopt.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>

#include "proxy_wasm_enums.h"

#define WASM_DEBUG_TAG "wasm"

struct WasmInstanceConfig {
  std::string wasm_filename;
};

#define TS_WASM_HTTP_FETCH_SUCCESS ((TsEvent)(-1000))
#define TS_WASM_HTTP_FETCH_FAILURE ((TsEvent)(-1001))
#define TS_WASM_HTTP_FETCH_TIMEOUT ((TsEvent)(-1002))

static inline int read_file(std::string fn, std::string* s) {
  auto fd = open(fn.c_str(), O_RDONLY | O_NOATIME, 00660);
  if (fd < 0) {
    return -1;
  }
  auto n = ::lseek(fd, 0, SEEK_END);
  ::lseek(fd, 0, SEEK_SET);
  s->reserve(n);
  auto nn = ::read(fd, (char*)s->begin(), n);
  if (nn != (ssize_t)n) {
    return -1;
  }
  return 0;
}

#if 0
TSReturnCode
TSRemapInit(TSRemapInterface *api_info, char *errbuf, int errbuf_size)
{
  return TS_SUCCESS;
}

void
TSRemapDone(void)
{
}

TSReturnCode
TSRemapNewInstance(int argc, char *argv[], void **ih, char *errbuf, int errbuf_size)
{
  return TS_SUCCESS;
}

void
TSRemapDeleteInstance(void *ih)
{
}

static TSRemapStatus
ts_lua_remap_plugin_init(void *ih, TSHttpTxn rh, TSRemapRequestInfo *rri)
{
  return TSREMAP_NO_REMAP;
}

void
TSRemapOSResponse(void *ih, TSHttpTxn rh, int os_response_type)
{
}

TSRemapStatus
TSRemapDoRemap(void *ih, TSHttpTxn rh, TSRemapRequestInfo *rri)
{
}
#endif

#if 0
  TSMBuffer bufp;
  TSMLoc hdr_loc;
  TSMLoc url_loc;
  if (!http_ctx->client_request_bufp) {
    if (TSHttpTxnClientReqGet(txnp, &bufp, &hdr_loc) == TS_SUCCESS) {
      http_ctx->client_request_bufp = bufp;
      http_ctx->client_request_hdrp = hdr_loc;
      if (TSHttpHdrUrlGet(bufp, hdr_loc, &url_loc) == TS_SUCCESS) {
        http_ctx->client_request_url = url_loc;
      }
    }
  }
#endif

int
http_event_handler(TSCont contp, TSEvent event, void *data)
{
  TSHttpTxn txnp;
  auto context = (Context*)TSContDataGet(contp);

  TSMutexLock(context->global_mutex());

  switch (event) {

  case TS_EVENT_HTTP_POST_REMAP:
    break;

  case TS_EVENT_HTTP_CACHE_LOOKUP_COMPLETE:
    break;

  case TS_EVENT_HTTP_SEND_REQUEST_HDR:
    break;

  case TS_EVENT_HTTP_READ_RESPONSE_HDR:
    break;

  case TS_EVENT_HTTP_SEND_RESPONSE_HDR:
    break;

  case TS_EVENT_HTTP_READ_REQUEST_HDR:
    break;

  case TS_EVENT_HTTP_TXN_START:
    break;

  case TS_EVENT_HTTP_PRE_REMAP:
    break;

  case TS_EVENT_HTTP_OS_DNS:
    break;

  case TS_EVENT_HTTP_READ_CACHE_HDR:
    break;

  case TS_EVENT_HTTP_TXN_CLOSE:
    break;

  case TS_WASM_HTTP_FETCH_SUCCESS:
    break;

  case TS_WASM_HTTP_FETCH_FAILURE:
    break;

  case TS_WASM_HTTP_FETCH_TIMEOUT:
    break;

  default:
    break;
  }

  TSMutexUnlock(ccontext->global_mutex());

  if (result == 0) {
    TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
  } else if (result < 0) {
    TSHttpTxnReenable(txnp, TS_EVENT_HTTP_ERROR);
  } else {
    // wait for async operation
  }
  return 0;
}

Context::Context(TSCont global_contp, TSHttpTxn txnp) {
  auto config = (WasmInstanceConfig *)TSContDataGet(global_contp);

  TSCont txn_contp = TSContCreate(http_event_handler, nullptr);
  TSHttpTxnHookAdd(txnp, TS_HTTP_CACHE_LOOKUP_COMPLETE_HOOK, txn_contp);
  TSHttpTxnHookAdd(txnp, TS_HTTP_READ_REQUEST_HDR_HOOK, txn_contp);
  TSHttpTxnHookAdd(txnp, TS_HTTP_PRE_REMAP_HOOK, txn_contp);
  TSHttpTxnHookAdd(txnp, TS_HTTP_POST_REMAP_HOOK, txn_contp);
  TSHttpTxnHookAdd(txnp, TS_HTTP_OS_DNS_HOOK, txn_contp);
  TSHttpTxnHookAdd(txnp, TS_HTTP_REQUEST_TRANSFORM_HOOK, txn_contp);
  TSHttpTxnHookAdd(txnp, TS_HTTP_SEND_REQUEST_HDR_HOOK, txn_contp);
  TSHttpTxnHookAdd(txnp, TS_HTTP_READ_CACHE_HDR_HOOK, txn_contp);
  TSHttpTxnHookAdd(txnp, TS_HTTP_READ_RESPONSE_HDR_HOOK, txn_contp);
  TSHttpTxnHookAdd(txnp, TS_HTTP_SEND_RESPONSE_HDR_HOOK, txn_contp);
  TSHttpTxnHookAdd(txnp, TS_HTTP_RESPONSE_TRANSFORM_HOOK, txn_contp);
  TSHttpTxnHookAdd(txnp, TS_HTTP_TXN_CLOSE_HOOK, txn_contp);
}

static void
reloadWasm(WasmInstanceConfig *config ATS_UNUSED)
{
  TSDebug(WASM_DEBUG_TAG, "[%s] ignoring reload for now", __FUNCTION__);
}

static int
configHandler(TSCont contp, TSEvent event ATS_UNUSED, void *edata ATS_UNUSED)
{
  TSDebug(WASM_DEBUG_TAG, "[%s] calling configuration handler", __FUNCTION__);
  auto *config = (WasmInstanceConfig *)TSContDataGet(contp);
  reloadWasm(config);
  return 0;
}

static int
globalHookHandler(TSCont contp, TSEvent event, void *data)
{
  TSDebug(WASM_DEBUG_FLAG, "[%s]: %d", __FUNCTION__, (int)event);
  TSContDataSet(txn_contp, new Context(contp, (TSHttpTxn)data);
  TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
  return 0;
}

void
TSPluginInit(int argc, const char *argv[])
{
  TSPluginRegistrationInfo info;
  info.plugin_name   = "wasm";
  info.vendor_name   = "Apache Software Foundation";
  info.support_email = "dev@trafficserver.apache.org";
  if (TSPluginRegister(&info) != TS_SUCCESS) {
    TSError("[wasm] Plugin registration failed");
  }

  int loglevel                         = 0;
  int reload                           = 0;
  static const struct option longopt[] = {
    {"loglevel", required_argument, 0, 'l'},
    {"enable-reload", no_argument, 0, 'r'},
    {0, 0, 0, 0},
  };

  while (true) {
    int opt = getopt_long(argc, (char *const *)argv, "", longopt, nullptr);
    switch (opt) {
    case 'l':
      loglevel = atoi(optarg);
      break;
    case 'r':
      reload = 1;
      TSDebug(WASM_DEBUG_TAG, "[%s] enable global plugin reload [%d]", __FUNCTION__, reload);
      break;
    }
    if (opt == -1) {
      break;
    }
  }

  if (loglevel > (int)LogLevel::critical) {
    TSError("[wasm][%s] invalid loglevel: %d", __FUNCTION__, loglevel);
    return;
  }

  if (argc - optind < 1) {
    TSError("[wasm][%s] wasm file argument missing", __FUNCTION__);
    return;
  }

  auto config = std::unique_ptr<WasmInstanceConfig>((WasmInstanceConfig *)TSmalloc(sizeof(WasmInstanceConfig)));

  config->wasm_filename = std::string(argv[optind]);
  if (*config->wasm_filename.begin() != '/') {
    config->wasm_filename = std::string(TSConfigDirGet()) + "/" + config->wasm_filename;
  }
  auto wasm_vm = createWasmVm("wavm");
  std::string code;
  if (read_file(config->wasm_filename, &code) < 0) {
    TSError("[wasm][%s] wasm unable to read file '%s'", __FUNCTION__, config->wasm_filename.c_str());
    return;
  }
  if (!wasm_vm->load(code, true)) {
    TSError("[wasm][%s] wasm unable to load file '%s'", __FUNCTION__, config->wasm_filename.c_str());
    return;
  }
  wasm_vm->link("wasm");


  TSCont global_contp = TSContCreate(globalHookHandler, nullptr);
  if (!global_contp) {
    TSError("[wasm][%s] could not create transaction start continuation", __FUNCTION__);
    return;
  }
  TSContDataSet(global_contp, config.release());
  TSHttpHookAdd(TS_HTTP_TXN_START_HOOK, global_contp);

  if (reload) {
    TSCont config_contp = TSContCreate(configHandler, nullptr);
    if (!config_contp) {
      TSError("[wasm][%s] could not create configuration continuation", __FUNCTION__);
      return;
    }
    TSContDataSet(config_contp, config.release());
    TSMgmtUpdateRegister(config_contp, "wasm");
  }
}
