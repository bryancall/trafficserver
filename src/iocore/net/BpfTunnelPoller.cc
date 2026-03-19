/** @file

  BPF tunnel poller implementation.

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

#include "tscore/ink_config.h"

#if TS_USE_BPF_SOCKMAP

#include "BpfTunnelPoller.h"
#include "BpfSockmapManager.h"
#include "BpfTunnelRegistry.h"

#include "iocore/eventsystem/EThread.h"
#include "iocore/eventsystem/EventProcessor.h"
#include "tscore/Diags.h"

#include "bpf/sockmap_tunnel.h"

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>

namespace
{
DbgCtl dbg_ctl_bpf_poller{"bpf_sockmap_poller"};

/**
 * Ring buffer callback invoked by libbpf for each event.
 * The ctx pointer is the BpfTunnelPoller instance.
 */
int
ringbuf_event_handler(void *ctx, void *data, size_t data_sz)
{
  if (data_sz < sizeof(struct tunnel_event)) {
    return 0;
  }

  auto *evt = static_cast<struct tunnel_event *>(data);

  if (evt->event == TUNNEL_EVENT_CLOSE) {
    auto info = BpfTunnelRegistry::lookup_by_cookie(evt->cookie);
    if (info) {
      Dbg(dbg_ctl_bpf_poller, "ring buffer close event for tunnel %" PRIu64 " (cookie %" PRIu64 ")", info->tunnel_id, evt->cookie);

      // Remove from BPF maps
      BpfSockmapManager::remove_tunnel(info->tunnel_id);

      // Close the sockets to trigger normal ATS VConnection cleanup.
      // The VConnections still own these FDs and will detect the close
      // via their next I/O attempt or via the event system.
      // We shutdown rather than close to signal the peer cleanly.
      ::shutdown(info->client_fd, SHUT_RDWR);
      ::shutdown(info->origin_fd, SHUT_RDWR);
    }
  }

  return 0;
}

} // anonymous namespace

BpfTunnelPoller::BpfTunnelPoller()
{
  SET_HANDLER(&BpfTunnelPoller::mainEvent);
  mutex = new_ProxyMutex();
}

BpfTunnelPoller::~BpfTunnelPoller()
{
  stop();
}

bool
BpfTunnelPoller::init()
{
  int fd = BpfSockmapManager::get_ringbuf_fd();
  if (fd < 0) {
    Warning("BPF poller: invalid ring buffer FD");
    return false;
  }

  ringbuf_ = ring_buffer__new(fd, ringbuf_event_handler, this, nullptr);
  if (!ringbuf_) {
    Warning("BPF poller: failed to create ring buffer consumer: %s", strerror(errno));
    return false;
  }

  Dbg(dbg_ctl_bpf_poller, "ring buffer consumer initialized");
  return true;
}

void
BpfTunnelPoller::start()
{
  // Schedule periodic event every 100ms on an ET_NET thread
  poll_event_ = eventProcessor.schedule_every(this, HRTIME_MSECONDS(100), ET_NET);
  Dbg(dbg_ctl_bpf_poller, "polling started (100ms interval)");
}

void
BpfTunnelPoller::stop()
{
  if (poll_event_) {
    poll_event_->cancel();
    poll_event_ = nullptr;
  }

  if (ringbuf_) {
    ring_buffer__free(ringbuf_);
    ringbuf_ = nullptr;
  }

  Dbg(dbg_ctl_bpf_poller, "polling stopped");
}

int
BpfTunnelPoller::mainEvent(int event, Event * /* e ATS_UNUSED */)
{
  drain_ring_buffer();

  poll_count_++;
  if (poll_count_ >= LIVENESS_CHECK_INTERVAL) {
    poll_count_ = 0;
    liveness_check();
  }

  return EVENT_CONT;
}

void
BpfTunnelPoller::drain_ring_buffer()
{
  if (!ringbuf_) {
    return;
  }

  // Consume all available events (non-blocking)
  int consumed = ring_buffer__consume(ringbuf_);
  if (consumed > 0) {
    Dbg(dbg_ctl_bpf_poller, "consumed %d ring buffer events", consumed);
  }
}

void
BpfTunnelPoller::liveness_check()
{
  // TODO: iterate sock_stats map, compare with previous snapshot,
  // detect stale tunnels with zero byte delta over threshold.
  // For now, the ring buffer handles the common case.
  Dbg(dbg_ctl_bpf_poller, "liveness check (%zu active tunnels)", BpfTunnelRegistry::size());
}

#endif /* TS_USE_BPF_SOCKMAP */
