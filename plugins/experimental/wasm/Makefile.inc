#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information
#  regarding copyright ownership.  The ASF licenses this file
#  to you under the Apache License, Version 2.0 (the
#  "License"); you may not use this file except in compliance
#  with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

experimental_wasm_wasm_la_CPPFLAGS = $(AM_CPPFLAGS) $(WAVM_CPPFLAGS) -DWAVM_API=
experimental_wasm_wasm_la_LDFLAGS = = $(AM_LDFLAGS) $(WAVM_LDFLAGS)

pkglib_LTLIBRARIES += experimental/wasm/wasm.la

experimental_wasm_wasm_la_SOURCES = \
  experimental/wasm/proxy_wasm_enums.h \
  experimental/wasm/wasm_vm.cc \
  experimental/wasm/wasm_vm.h \
  experimental/wasm/wasm.cc \
  experimental/wasm/wasm.h \
  experimental/wasm/wasm_main.cc \
  experimental/wasm/wasm.h \
  experimental/wasm/wavm.cc \
  experimental/wasm/wavm.h

check_PROGRAMS += experimental/wasm/test_wasm

experimental_wasm_test_wasm_CPPFLAGS = $(AM_CPPFLAGS) -I$(abs_top_srcdir)/tests/include -DUNITTEST
experimental_wasm_test_wasm_SOURCES = \
  experimental/wasm/test_wasm.cc
