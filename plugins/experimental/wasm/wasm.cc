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

#include "proxy_wasm_enums.h"

#define WASM_DEBUG_TAG "wasm"

struct WasmInstanceConfig {
  std::string wasm_filename;
};

#if 0
TSReturnCode
TSRemapInit(TSRemapInterface *api_info, char *errbuf, int errbuf_size)
{
  if (!api_info || api_info->size < sizeof(TSRemapInterface)) {
    strncpy(errbuf, "[TSRemapInit] - Incorrect size of TSRemapInterface structure", errbuf_size - 1);
    errbuf[errbuf_size - 1] = '\0';
    return TS_ERROR;
  }

  if (ts_lua_main_ctx_array != NULL) {
    return TS_SUCCESS;
  }

  ts_lua_main_ctx_array = TSmalloc(sizeof(ts_lua_main_ctx) * TS_LUA_MAX_STATE_COUNT);
  memset(ts_lua_main_ctx_array, 0, sizeof(ts_lua_main_ctx) * TS_LUA_MAX_STATE_COUNT);

  ret = ts_lua_create_vm(ts_lua_main_ctx_array, TS_LUA_MAX_STATE_COUNT);

  if (ret) {
    TSfree(ts_lua_main_ctx_array);
    return TS_ERROR;
  }

  return TS_SUCCESS;
}

void
TSRemapDone(void)
{
}

TSReturnCode
TSRemapNewInstance(int argc, char *argv[], void **ih, char *errbuf, int errbuf_size)
{
  int ret;
  char script[TS_LUA_MAX_SCRIPT_FNAME_LENGTH];
  char *inline_script                  = "";
  int fn                               = 0;
  int states                           = TS_LUA_MAX_STATE_COUNT;
  static const struct option longopt[] = {
    {"states", required_argument, 0, 's'},
    {"inline", required_argument, 0, 'i'},
    {0, 0, 0, 0},
  };

  argc--;
  argv++;

  for (;;) {
    int opt;

    opt = getopt_long(argc, (char *const *)argv, "", longopt, NULL);
    switch (opt) {
    case 's':
      states = atoi(optarg);
      TSDebug(TS_LUA_DEBUG_TAG, "[%s] setting number of lua VM [%d]", __FUNCTION__, states);
      // set state
      break;
    case 'i':
      inline_script = optarg;
    }

    if (opt == -1) {
      break;
    }
  }

  if (states > TS_LUA_MAX_STATE_COUNT || states < 1) {
    snprintf(errbuf, errbuf_size, "[TSRemapNewInstance] - invalid state in option input. Must be between 1 and %d",
             TS_LUA_MAX_STATE_COUNT);
    return TS_ERROR;
  }

  if (argc - optind > 0) {
    fn = 1;
    if (argv[optind][0] == '/') {
      snprintf(script, sizeof(script), "%s", argv[optind]);
    } else {
      snprintf(script, sizeof(script), "%s/%s", TSConfigDirGet(), argv[optind]);
    }
  }

  if (strlen(inline_script) == 0 && argc - optind < 1) {
    strncpy(errbuf, "[TSRemapNewInstance] - lua script file or string is required !!", errbuf_size - 1);
    errbuf[errbuf_size - 1] = '\0';
    return TS_ERROR;
  }

  if (strlen(script) >= TS_LUA_MAX_SCRIPT_FNAME_LENGTH - 16) {
    strncpy(errbuf, "[TSRemapNewInstance] - lua script file name too long !!", errbuf_size - 1);
    errbuf[errbuf_size - 1] = '\0';
    return TS_ERROR;
  }

  ts_lua_instance_conf *conf = NULL;

  // check to make sure it is a lua file and there is no parameter for the lua file
  if (fn && (argc - optind < 2)) {
    TSDebug(TS_LUA_DEBUG_TAG, "[%s] checking if script has been registered", __FUNCTION__);

    // we only need to check the first lua VM for script registration
    conf = ts_lua_script_registered(ts_lua_main_ctx_array[0].lua, script);
  }

  if (!conf) {
    TSDebug(TS_LUA_DEBUG_TAG, "[%s] creating new conf instance", __FUNCTION__);

    conf = TSmalloc(sizeof(ts_lua_instance_conf));
    if (!conf) {
      strncpy(errbuf, "[TSRemapNewInstance] TSmalloc failed!!", errbuf_size - 1);
      errbuf[errbuf_size - 1] = '\0';
      return TS_ERROR;
    }

    memset(conf, 0, sizeof(ts_lua_instance_conf));
    conf->states    = states;
    conf->remap     = 1;
    conf->init_func = 0;

    if (fn) {
      snprintf(conf->script, TS_LUA_MAX_SCRIPT_FNAME_LENGTH, "%s", script);
    } else {
      conf->content = inline_script;
    }

    ts_lua_init_instance(conf);

    ret = ts_lua_add_module(conf, ts_lua_main_ctx_array, conf->states, argc - optind, &argv[optind], errbuf, errbuf_size);

    if (ret != 0) {
      return TS_ERROR;
    }

    // register the script only if it is from a file and has no __init__ function
    if (fn && !conf->init_func) {
      // we only need to register the script for the first lua VM
      ts_lua_script_register(ts_lua_main_ctx_array[0].lua, conf->script, conf);
    }
  }

  *ih = conf;

  return TS_SUCCESS;
}

void
TSRemapDeleteInstance(void *ih)
{
  int states = ((ts_lua_instance_conf *)ih)->states;
  ts_lua_del_module((ts_lua_instance_conf *)ih, ts_lua_main_ctx_array, states);
  ts_lua_del_instance(ih);
  // because we now reuse ts_lua_instance_conf / ih for remap rules sharing the same lua script
  // we cannot safely free it in this function during the configuration reloads
  // we therefore are leaking memory on configuration reloads
  return;
}

static TSRemapStatus
ts_lua_remap_plugin_init(void *ih, TSHttpTxn rh, TSRemapRequestInfo *rri)
{
  int ret;
  uint64_t req_id;

  TSCont contp;
  lua_State *L;

  ts_lua_main_ctx *main_ctx;
  ts_lua_http_ctx *http_ctx;
  ts_lua_cont_info *ci;

  ts_lua_instance_conf *instance_conf;

  int remap     = (rri == NULL ? 0 : 1);
  instance_conf = (ts_lua_instance_conf *)ih;
  req_id        = __sync_fetch_and_add(&ts_lua_http_next_id, 1);

  main_ctx = &ts_lua_main_ctx_array[req_id % instance_conf->states];

  TSMutexLock(main_ctx->mutexp);

  http_ctx = ts_lua_create_http_ctx(main_ctx, instance_conf);

  http_ctx->txnp     = rh;
  http_ctx->has_hook = 0;
  http_ctx->rri      = rri;
  if (rri != NULL) {
    http_ctx->client_request_bufp = rri->requestBufp;
    http_ctx->client_request_hdrp = rri->requestHdrp;
    http_ctx->client_request_url  = rri->requestUrl;
  }

  ci = &http_ctx->cinfo;
  L  = ci->routine.lua;

  contp = TSContCreate(ts_lua_http_cont_handler, NULL);
  TSContDataSet(contp, http_ctx);

  ci->contp = contp;
  ci->mutex = TSContMutexGet((TSCont)rh);

  lua_getglobal(L, (remap ? TS_LUA_FUNCTION_REMAP : TS_LUA_FUNCTION_OS_RESPONSE));
  if (lua_type(L, -1) != LUA_TFUNCTION) {
    lua_pop(L, 1);
    ts_lua_destroy_http_ctx(http_ctx);
    TSMutexUnlock(main_ctx->mutexp);
    return TSREMAP_NO_REMAP;
  }

  ts_lua_set_cont_info(L, NULL);
  if (lua_pcall(L, 0, 1, 0) != 0) {
    TSError("[ts_lua] lua_pcall failed: %s", lua_tostring(L, -1));
    ret = TSREMAP_NO_REMAP;

  } else {
    ret = lua_tointeger(L, -1);
  }

  lua_pop(L, 1);

  if (http_ctx->has_hook) {
    TSDebug(TS_LUA_DEBUG_TAG, "[%s] has txn hook -> adding txn close hook handler to release resources", __FUNCTION__);
    TSHttpTxnHookAdd(rh, TS_HTTP_TXN_CLOSE_HOOK, contp);
  } else {
    TSDebug(TS_LUA_DEBUG_TAG, "[%s] no txn hook -> release resources now", __FUNCTION__);
    ts_lua_destroy_http_ctx(http_ctx);
  }

  TSMutexUnlock(main_ctx->mutexp);

  return ret;
}

void
TSRemapOSResponse(void *ih, TSHttpTxn rh, int os_response_type)
{
  TSDebug(TS_LUA_DEBUG_TAG, "[%s] os response function and type - %d", __FUNCTION__, os_response_type);
  ts_lua_remap_plugin_init(ih, rh, NULL);
}

TSRemapStatus
TSRemapDoRemap(void *ih, TSHttpTxn rh, TSRemapRequestInfo *rri)
{
  TSDebug(TS_LUA_DEBUG_TAG, "[%s] remap function", __FUNCTION__);
  return ts_lua_remap_plugin_init(ih, rh, rri);
}
#endif

static void
reloadWasm(WasmInstanceConfig *config)
{
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
globalHookHandler(TSCont contp ATS_UNUSED, TSEvent event ATS_UNUSED, void *edata ATS_UNUSED)
{
#if 0
  TSHttpTxn txnp = (TSHttpTxn)edata;

  TSMBuffer bufp;
  TSMLoc hdr_loc;
  TSMLoc url_loc;

  int ret;
  uint64_t req_id;
  TSCont txn_contp;

  auto config = (WasmInstanceConfig *)TSContDataGet(contp);

  req_id = __sync_fetch_and_add(&ts_lua_g_http_next_id, 1);

  TSDebug(TS_LUA_DEBUG_TAG, "[%s] req_id: %" PRId64, __FUNCTION__, req_id);
  TSMutexLock(main_ctx->mutexp);

  http_ctx           = ts_lua_create_http_ctx(main_ctx, conf);
  http_ctx->txnp     = txnp;
  http_ctx->rri      = NULL;
  http_ctx->has_hook = 0;

  if (!http_ctx->client_request_bufp) {
    if (TSHttpTxnClientReqGet(txnp, &bufp, &hdr_loc) == TS_SUCCESS) {
      http_ctx->client_request_bufp = bufp;
      http_ctx->client_request_hdrp = hdr_loc;

      if (TSHttpHdrUrlGet(bufp, hdr_loc, &url_loc) == TS_SUCCESS) {
        http_ctx->client_request_url = url_loc;
      }
    }
  }

  if (!http_ctx->client_request_hdrp) {
    ts_lua_destroy_http_ctx(http_ctx);
    TSMutexUnlock(main_ctx->mutexp);

    TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
    return 0;
  }

  txn_contp = TSContCreate(ts_lua_http_cont_handler, NULL);
  TSContDataSet(txn_contp, http_ctx);

  ci        = &http_ctx->cinfo;
  ci->contp = txn_contp;
  ci->mutex = TSContMutexGet((TSCont)txnp);

  l = ci->routine.lua;

  switch (event) {
  case TS_EVENT_HTTP_READ_REQUEST_HDR:
    lua_getglobal(l, TS_LUA_FUNCTION_G_READ_REQUEST);
    break;

  case TS_EVENT_HTTP_SEND_REQUEST_HDR:
    lua_getglobal(l, TS_LUA_FUNCTION_G_SEND_REQUEST);
    break;

  case TS_EVENT_HTTP_READ_RESPONSE_HDR:
    lua_getglobal(l, TS_LUA_FUNCTION_G_READ_RESPONSE);
    break;

  case TS_EVENT_HTTP_SEND_RESPONSE_HDR:
    // client response can be changed within a transaction
    // (e.g. due to the follow redirect feature). So, clearing the pointers
    // to allow API(s) to fetch the pointers again when it re-enters the hook
    if (http_ctx->client_response_hdrp != NULL) {
      TSHandleMLocRelease(http_ctx->client_response_bufp, TS_NULL_MLOC, http_ctx->client_response_hdrp);
      http_ctx->client_response_hdrp = NULL;
    }
    lua_getglobal(l, TS_LUA_FUNCTION_G_SEND_RESPONSE);
    break;

  case TS_EVENT_HTTP_CACHE_LOOKUP_COMPLETE:
    lua_getglobal(l, TS_LUA_FUNCTION_G_CACHE_LOOKUP_COMPLETE);
    break;

  case TS_EVENT_HTTP_TXN_START:
    lua_getglobal(l, TS_LUA_FUNCTION_G_TXN_START);
    break;

  case TS_EVENT_HTTP_PRE_REMAP:
    lua_getglobal(l, TS_LUA_FUNCTION_G_PRE_REMAP);
    break;

  case TS_EVENT_HTTP_POST_REMAP:
    lua_getglobal(l, TS_LUA_FUNCTION_G_POST_REMAP);
    break;

  case TS_EVENT_HTTP_OS_DNS:
    lua_getglobal(l, TS_LUA_FUNCTION_G_OS_DNS);
    break;

  case TS_EVENT_HTTP_READ_CACHE_HDR:
    lua_getglobal(l, TS_LUA_FUNCTION_G_READ_CACHE);
    break;

  case TS_EVENT_HTTP_TXN_CLOSE:
    lua_getglobal(l, TS_LUA_FUNCTION_G_TXN_CLOSE);
    break;

  default:
    ts_lua_destroy_http_ctx(http_ctx);
    TSMutexUnlock(main_ctx->mutexp);
    TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
    return 0;
  }

  if (lua_type(l, -1) != LUA_TFUNCTION) {
    lua_pop(l, 1);
    ts_lua_destroy_http_ctx(http_ctx);
    TSMutexUnlock(main_ctx->mutexp);

    TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
    return 0;
  }

  ts_lua_set_cont_info(l, NULL);

  if (lua_pcall(l, 0, 1, 0) != 0) {
    TSError("[ts_lua] lua_pcall failed: %s", lua_tostring(l, -1));
  }

  ret = lua_tointeger(l, -1);
  lua_pop(l, 1);

  if (http_ctx->has_hook) {
    // add a hook to release resources for context
    TSDebug(TS_LUA_DEBUG_TAG, "[%s] has txn hook -> adding txn close hook handler to release resources", __FUNCTION__);
    TSHttpTxnHookAdd(txnp, TS_HTTP_TXN_CLOSE_HOOK, txn_contp);
  } else {
    TSDebug(TS_LUA_DEBUG_TAG, "[%s] no txn hook -> release resources now", __FUNCTION__);
    ts_lua_destroy_http_ctx(http_ctx);
  }

  TSMutexUnlock(main_ctx->mutexp);

  if (ret) {
    TSHttpTxnReenable(txnp, TS_EVENT_HTTP_ERROR);
  } else {
    TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
  }

#endif
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
    int opt = getopt_long(argc, (char *const *)argv, "", longopt, NULL);
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

  TSCont global_contp = TSContCreate(globalHookHandler, NULL);
  if (!global_contp) {
    TSError("[wasm][%s] could not create transaction start continuation", __FUNCTION__);
    return;
  }
  TSContDataSet(global_contp, config.release());

#if 0
  TSHttpHookAdd(TS_HTTP_SEND_REQUEST_HDR_HOOK, global_contp);
  TSDebug(WASM_DEBUG_TAG, "send_request_hdr_hook added");
  TSHttpHookAdd(TS_HTTP_READ_RESPONSE_HDR_HOOK, global_contp);
  TSDebug(TS_LUA_DEBUG_TAG, "read_response_hdr_hook added");
  TSHttpHookAdd(TS_HTTP_SEND_RESPONSE_HDR_HOOK, global_contp);
  TSDebug(TS_LUA_DEBUG_TAG, "send_response_hdr_hook added");
  TSHttpHookAdd(TS_HTTP_CACHE_LOOKUP_COMPLETE_HOOK, global_contp);
  TSDebug(TS_LUA_DEBUG_TAG, "cache_lookup_complete_hook added");
  TSHttpHookAdd(TS_HTTP_READ_REQUEST_HDR_HOOK, global_contp);
  TSDebug(TS_LUA_DEBUG_TAG, "read_request_hdr_hook added");
  TSHttpHookAdd(TS_HTTP_TXN_START_HOOK, global_contp);
  TSDebug(TS_LUA_DEBUG_TAG, "txn_start_hook added");
  TSHttpHookAdd(TS_HTTP_PRE_REMAP_HOOK, global_contp);
  TSDebug(TS_LUA_DEBUG_TAG, "pre_remap_hook added");
  TSHttpHookAdd(TS_HTTP_POST_REMAP_HOOK, global_contp);
  TSDebug(TS_LUA_DEBUG_TAG, "post_remap_hook added");
  TSHttpHookAdd(TS_HTTP_OS_DNS_HOOK, global_contp);
  TSDebug(TS_LUA_DEBUG_TAG, "os_dns_hook added");
  TSHttpHookAdd(TS_HTTP_READ_CACHE_HDR_HOOK, global_contp);
  TSDebug(TS_LUA_DEBUG_TAG, "read_cache_hdr_hook added");
  TSHttpHookAdd(TS_HTTP_TXN_CLOSE_HOOK, global_contp);
  TSDebug(TS_LUA_DEBUG_TAG, "txn_close_hook added");
#endif

  // support for reload as global plugin
  if (reload) {
    TSCont config_contp = TSContCreate(configHandler, NULL);
    if (!config_contp) {
      TSError("[wasm][%s] could not create configuration continuation", __FUNCTION__);
      return;
    }
    TSContDataSet(config_contp, config.release());
    TSMgmtUpdateRegister(config_contp, "wasm");
  }
}
