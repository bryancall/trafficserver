/** @file

  Periodic poller for BPF sockmap tunnel events.

  @section license License

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

#pragma once

#include "tscore/ink_config.h"

#if TS_USE_BPF_SOCKMAP

#include "iocore/eventsystem/Continuation.h"
#include "iocore/eventsystem/Event.h"

struct ring_buffer;

/**
 * Periodic Continuation that consumes BPF ring buffer events and
 * triggers tunnel teardown in ATS.
 *
 * Scheduled on an ET_NET thread at 100ms intervals. When a socket
 * close event arrives via the ring buffer, the poller:
 *   1. Looks up the cookie in BpfTunnelRegistry
 *   2. Calls BpfSockmapManager::remove_tunnel()
 *   3. Closes both socket FDs to trigger normal ATS cleanup
 *
 * Also performs periodic liveness checks on stale tunnels.
 */
class BpfTunnelPoller : public Continuation
{
public:
  BpfTunnelPoller();
  ~BpfTunnelPoller();

  /** Initialize the ring buffer consumer. Returns false on failure. */
  bool init();

  /** Start periodic polling. */
  void start();

  /** Stop polling and clean up. */
  void stop();

private:
  int mainEvent(int event, Event *e);

  /** Process all pending ring buffer events. */
  void drain_ring_buffer();

  /** Check for stale tunnels that may have been missed by ring buffer. */
  void liveness_check();

  struct ring_buffer *ringbuf_    = nullptr;
  Event              *poll_event_ = nullptr;
  int                 poll_count_ = 0;

  static constexpr int LIVENESS_CHECK_INTERVAL = 50; // every 50 polls (~5 seconds)
};

#endif /* TS_USE_BPF_SOCKMAP */
