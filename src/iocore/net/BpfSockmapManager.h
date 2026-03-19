/** @file

  BPF sockmap manager for kernel-level blind tunnel acceleration.

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

#include <atomic>
#include <cstdint>

#include "bpf/sockmap_tunnel.h"

struct bpf_object;

/**
 * Manages BPF sockmap programs and maps for blind tunnel acceleration.
 *
 * Loads BPF programs before privilege drop, then uses stored map FDs
 * to insert/remove socket pairs at runtime. Thread-safe for insert/remove
 * operations via atomic index allocation.
 *
 * Usage:
 *   BpfSockmapManager::init()           // before privilege drop
 *   BpfSockmapManager::insert_tunnel()  // from HttpSM context
 *   BpfSockmapManager::remove_tunnel()  // from poller or HttpSM
 *   BpfSockmapManager::shutdown()       // at process exit
 */
class BpfSockmapManager
{
public:
  /** Initialize BPF programs and maps. Must be called before privilege drop. */
  static bool init();

  /** Detach programs and close map FDs. */
  static void shutdown();

  /** Check if BPF sockmap acceleration is available and initialized. */
  static bool is_available();

  /**
   * Insert a tunnel socket pair into the sockmap.
   *
   * Both FDs are added to the sockmap and cross-referenced in sock_pair.
   * On success, the sockets should be removed from epoll.
   *
   * @param client_fd  Client-side socket file descriptor
   * @param origin_fd  Origin-side socket file descriptor
   * @param tunnel_id  Unique tunnel identifier (typically HttpSM::sm_id)
   * @return true on success, false on failure (caller should fall back to userspace)
   */
  static bool insert_tunnel(int client_fd, int origin_fd, uint64_t tunnel_id);

  /**
   * Remove a tunnel socket pair from the sockmap.
   *
   * Cleans up all BPF map entries. After removal, sockets return to
   * normal kernel behavior and can be closed normally.
   *
   * @param tunnel_id  Tunnel identifier passed to insert_tunnel()
   */
  static void remove_tunnel(uint64_t tunnel_id);

  /** Get aggregate stats for all active BPF tunnels. */
  struct AggregateStats {
    uint64_t active_tunnels;
    uint64_t total_tunnels;
    uint64_t total_bytes;
    uint64_t fallback_count;
    uint64_t error_count;
  };
  static AggregateStats get_aggregate_stats();

  /** Get the ring buffer FD for the poller to consume events. */
  static int get_ringbuf_fd();

  /** Get the sockmap FD (for epoll removal coordination). */
  static int get_sockmap_fd();

  /** Get map FDs for direct access (used by poller for stats iteration). */
  static int get_stats_fd();
  static int get_pair_fd();

private:
  static struct bpf_object *obj_;
  static int                sockmap_fd_;
  static int                pair_fd_;
  static int                stats_fd_;
  static int                ringbuf_fd_;
  static bool               available_;

  static std::atomic<uint32_t> next_index_;

  // Aggregate counters
  static std::atomic<uint64_t> active_tunnels_;
  static std::atomic<uint64_t> total_tunnels_;
  static std::atomic<uint64_t> total_bytes_;
  static std::atomic<uint64_t> fallback_count_;
  static std::atomic<uint64_t> error_count_;
};

#endif /* TS_USE_BPF_SOCKMAP */
