/** @file

  Registry mapping socket cookies to tunnel metadata for BPF sockmap tunnels.

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

#include <cstdint>
#include <mutex>
#include <optional>
#include <unordered_map>

#include "tscore/ink_hrtime.h"

/**
 * Metadata for a single BPF-managed tunnel.
 */
struct BpfTunnelInfo {
  uint64_t   tunnel_id;
  int        client_fd;
  int        origin_fd;
  uint64_t   client_cookie;
  uint64_t   origin_cookie;
  uint32_t   client_idx;
  uint32_t   origin_idx;
  ink_hrtime start_time;
};

/**
 * Thread-safe registry of active BPF tunnels.
 *
 * Provides lookup by tunnel_id or socket cookie. Used by BpfTunnelPoller
 * to map ring buffer events (which carry socket cookies) back to tunnel
 * metadata for cleanup.
 */
class BpfTunnelRegistry
{
public:
  static void register_tunnel(uint64_t tunnel_id, int client_fd, int origin_fd, uint64_t client_cookie, uint64_t origin_cookie,
                              uint32_t client_idx, uint32_t origin_idx);

  static void unregister_tunnel(uint64_t tunnel_id);

  /** Look up tunnel info by tunnel ID. Returns nullopt if not found. */
  static std::optional<BpfTunnelInfo> lookup_by_tunnel_id(uint64_t tunnel_id);

  /** Look up tunnel info by socket cookie. Returns nullopt if not found. */
  static std::optional<BpfTunnelInfo> lookup_by_cookie(uint64_t cookie);

  /** Return number of active registered tunnels. */
  static size_t size();

private:
  static std::mutex                                  mutex_;
  static std::unordered_map<uint64_t, BpfTunnelInfo> by_tunnel_id_;
  static std::unordered_map<uint64_t, uint64_t>      cookie_to_tunnel_id_; // cookie -> tunnel_id
};

#endif /* TS_USE_BPF_SOCKMAP */
