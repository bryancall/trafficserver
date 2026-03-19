/** @file

  BPF tunnel registry implementation.

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

#include "BpfTunnelRegistry.h"

// Static member initialization
std::mutex                                  BpfTunnelRegistry::mutex_;
std::unordered_map<uint64_t, BpfTunnelInfo> BpfTunnelRegistry::by_tunnel_id_;
std::unordered_map<uint64_t, uint64_t>      BpfTunnelRegistry::cookie_to_tunnel_id_;

void
BpfTunnelRegistry::register_tunnel(uint64_t tunnel_id, int client_fd, int origin_fd, uint64_t client_cookie, uint64_t origin_cookie,
                                   uint32_t client_idx, uint32_t origin_idx)
{
  BpfTunnelInfo info;
  info.tunnel_id     = tunnel_id;
  info.client_fd     = client_fd;
  info.origin_fd     = origin_fd;
  info.client_cookie = client_cookie;
  info.origin_cookie = origin_cookie;
  info.client_idx    = client_idx;
  info.origin_idx    = origin_idx;
  info.start_time    = ink_get_hrtime();

  std::lock_guard<std::mutex> lock(mutex_);
  by_tunnel_id_[tunnel_id]            = info;
  cookie_to_tunnel_id_[client_cookie] = tunnel_id;
  cookie_to_tunnel_id_[origin_cookie] = tunnel_id;
}

void
BpfTunnelRegistry::unregister_tunnel(uint64_t tunnel_id)
{
  std::lock_guard<std::mutex> lock(mutex_);
  auto                        it = by_tunnel_id_.find(tunnel_id);
  if (it != by_tunnel_id_.end()) {
    cookie_to_tunnel_id_.erase(it->second.client_cookie);
    cookie_to_tunnel_id_.erase(it->second.origin_cookie);
    by_tunnel_id_.erase(it);
  }
}

std::optional<BpfTunnelInfo>
BpfTunnelRegistry::lookup_by_tunnel_id(uint64_t tunnel_id)
{
  std::lock_guard<std::mutex> lock(mutex_);
  auto                        it = by_tunnel_id_.find(tunnel_id);
  if (it != by_tunnel_id_.end()) {
    return it->second;
  }
  return std::nullopt;
}

std::optional<BpfTunnelInfo>
BpfTunnelRegistry::lookup_by_cookie(uint64_t cookie)
{
  std::lock_guard<std::mutex> lock(mutex_);
  auto                        cit = cookie_to_tunnel_id_.find(cookie);
  if (cit == cookie_to_tunnel_id_.end()) {
    return std::nullopt;
  }
  auto it = by_tunnel_id_.find(cit->second);
  if (it != by_tunnel_id_.end()) {
    return it->second;
  }
  return std::nullopt;
}

size_t
BpfTunnelRegistry::size()
{
  std::lock_guard<std::mutex> lock(mutex_);
  return by_tunnel_id_.size();
}

#endif /* TS_USE_BPF_SOCKMAP */
