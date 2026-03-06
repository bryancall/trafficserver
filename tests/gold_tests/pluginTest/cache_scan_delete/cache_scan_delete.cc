/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * cache_scan_delete.cc
 *
 * Test plugin for #12583: exercises TSCacheScan with DELETE_ALL_ALTERNATES
 * to verify that scan-delete works correctly with multiple cache volumes.
 *
 * Usage: cache_scan_delete.so <marker_file_path>
 *
 * When a request with header "X-Scan-Delete: start" is received, the plugin:
 *   1. Starts a TSCacheScan that deletes every object it finds
 *   2. Writes "scan_complete scanned=N" to the marker file when done
 *
 * The test checks for the marker file to verify the scan completed.
 */

#include <ts/ts.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>

#define PLUGIN_NAME "cache_scan_delete"

namespace
{
DbgCtl dbg_ctl{PLUGIN_NAME};

const char *g_marker_path = nullptr;

struct ScanState {
  int scanned = 0;
};

void
write_marker(int scanned)
{
  if (!g_marker_path) {
    return;
  }
  FILE *f = fopen(g_marker_path, "w");
  if (f) {
    fprintf(f, "scan_complete scanned=%d\n", scanned);
    fclose(f);
    Dbg(dbg_ctl, "wrote marker file: scanned=%d", scanned);
  } else {
    TSError("[%s] failed to write marker file %s", PLUGIN_NAME, g_marker_path);
  }
}

int
handle_scan(TSCont contp, TSEvent event, void * /* edata */)
{
  auto *state = static_cast<ScanState *>(TSContDataGet(contp));

  switch (event) {
  case TS_EVENT_CACHE_SCAN:
    Dbg(dbg_ctl, "scan started");
    return TS_EVENT_CONTINUE;

  case TS_EVENT_CACHE_SCAN_OBJECT:
    state->scanned++;
    Dbg(dbg_ctl, "scan object #%d — deleting all alternates", state->scanned);
    return TS_CACHE_SCAN_RESULT_DELETE_ALL_ALTERNATES;

  case TS_EVENT_CACHE_SCAN_DONE:
    Dbg(dbg_ctl, "scan complete: scanned=%d", state->scanned);
    write_marker(state->scanned);
    TSfree(state);
    TSContDestroy(contp);
    return TS_CACHE_SCAN_RESULT_DONE;

  case TS_EVENT_CACHE_SCAN_FAILED:
  case TS_EVENT_CACHE_SCAN_OPERATION_BLOCKED:
  case TS_EVENT_CACHE_SCAN_OPERATION_FAILED:
    Dbg(dbg_ctl, "scan failed/blocked event=%d", event);
    write_marker(-1);
    TSfree(state);
    TSContDestroy(contp);
    return TS_CACHE_SCAN_RESULT_DONE;

  default:
    break;
  }
  return TS_EVENT_CONTINUE;
}

int
global_handler(TSCont /* contp */, TSEvent event, void *edata)
{
  if (event != TS_EVENT_HTTP_READ_REQUEST_HDR) {
    TSHttpTxnReenable(static_cast<TSHttpTxn>(edata), TS_EVENT_HTTP_CONTINUE);
    return 0;
  }

  TSHttpTxn txnp = static_cast<TSHttpTxn>(edata);
  TSMBuffer bufp;
  TSMLoc    hdr_loc;

  if (TSHttpTxnClientReqGet(txnp, &bufp, &hdr_loc) != TS_SUCCESS) {
    TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
    return 0;
  }

  TSMLoc field_loc = TSMimeHdrFieldFind(bufp, hdr_loc, "X-Scan-Delete", -1);
  if (field_loc != TS_NULL_MLOC) {
    int         value_len = 0;
    const char *value     = TSMimeHdrFieldValueStringGet(bufp, hdr_loc, field_loc, 0, &value_len);

    if (value && value_len == 5 && memcmp(value, "start", 5) == 0) {
      Dbg(dbg_ctl, "received scan trigger header — starting cache scan");

      auto *state      = static_cast<ScanState *>(TSmalloc(sizeof(ScanState)));
      *state           = ScanState{};
      TSCont scan_cont = TSContCreate(handle_scan, TSMutexCreate());
      TSContDataSet(scan_cont, state);

      TSCacheScan(scan_cont, nullptr, 512000);
    }

    TSHandleMLocRelease(bufp, hdr_loc, field_loc);
  }

  TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc);
  TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
  return 0;
}

} // anonymous namespace

void
TSPluginInit(int argc, char const **argv)
{
  TSPluginRegistrationInfo info;
  info.plugin_name   = const_cast<char *>(PLUGIN_NAME);
  info.vendor_name   = const_cast<char *>("Apache");
  info.support_email = const_cast<char *>("dev@trafficserver.apache.org");

  if (TSPluginRegister(&info) != TS_SUCCESS) {
    TSError("[%s] Plugin registration failed", PLUGIN_NAME);
    return;
  }

  if (argc >= 2) {
    g_marker_path = TSstrdup(argv[1]);
  }

  TSHttpHookAdd(TS_HTTP_READ_REQUEST_HDR_HOOK, TSContCreate(global_handler, nullptr));
  Dbg(dbg_ctl, "initialized — send 'X-Scan-Delete: start' header to trigger cache scan + delete");
}
