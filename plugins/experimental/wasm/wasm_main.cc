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
#include <fcntl.h>

#include <string>

#include "proxy_wasm_enums.h"

#define WASM_DEBUG_TAG "wasm"

// This is one reason why python is more popular than C++.
// str = open(fn, 'r').read()
static inline int read_file(std::string fn, std::string* s) {
  auto fd = open(fn.c_str(), O_RDONLY);
  if (fd < 0) {
    return -1;
  }
  auto n = ::lseek(fd, 0, SEEK_END);
  ::lseek(fd, 0, SEEK_SET);
  s->resize(n);
  auto nn = ::read(fd, (char*)const_cast<char*>(&*s->begin()), n);
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

static void
reloadWasm(Wasm::WasmInstanceConfig *config)
{
  (void)config;
  TSDebug(WASM_DEBUG_TAG, "[%s] ignoring reload for now", __FUNCTION__);
}

static int
configHandler(TSCont contp, TSEvent event, void *data)
{
  (void)event;
  (void)data;
  TSDebug(WASM_DEBUG_TAG, "[%s] calling configuration handler", __FUNCTION__);
  auto *config = (Wasm::WasmInstanceConfig *)TSContDataGet(contp);
  reloadWasm(config);
  return 0;
}

static int
globalHookHandler(TSCont contp, TSEvent event, void *data)
{
  TSDebug(WASM_DEBUG_TAG, "[%s]: %d", __FUNCTION__, (int)event);
  auto config = (Wasm::WasmInstanceConfig *)TSContDataGet(contp);
  auto context = new Wasm::Context(config->wasm.get(), config->wasm->getRootContext("")->id());
  auto txnp = (TSHttpTxn)data;
  auto txn_contp = context->initialize(contp, txnp);
  TSContDataSet(txn_contp, context);
  context->onCreate();
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

  if (loglevel > (int)Wasm::LogLevel::critical) {
    TSError("[wasm][%s] invalid loglevel: %d", __FUNCTION__, loglevel);
    return;
  }

  if (argc - optind < 1) {
    TSError("[wasm][%s] wasm file argument missing", __FUNCTION__);
    return;
  }

  auto config = std::make_unique<Wasm::WasmInstanceConfig>();
  config->wasm_filename = std::string(argv[optind]);
  if (*config->wasm_filename.begin() != '/') {
    config->wasm_filename = std::string(TSConfigDirGet()) + "/" + config->wasm_filename;
  }
  std::string code;
  if (read_file(config->wasm_filename, &code) < 0) {
    TSError("[wasm][%s] wasm unable to read file '%s'", __FUNCTION__, config->wasm_filename.c_str());
    return;
  }
  config->wasm = Wasm::createWasm("", "wavm", code, "", "");
  if (!config->wasm) {
    TSError("[wasm][%s] wasm unable to create vm", __FUNCTION__);
    return;
  }

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
