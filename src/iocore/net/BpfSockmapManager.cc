/** @file

  BPF sockmap manager implementation.

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

#include "BpfSockmapManager.h"
#include "BpfTunnelRegistry.h"

#include "tscore/Diags.h"

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>

// Include the generated BPF skeleton
#include "sockmap_tunnel.skel.h"

namespace
{
DbgCtl dbg_ctl_bpf{"bpf_sockmap"};
}

// Static member initialization
struct bpf_object    *BpfSockmapManager::obj_        = nullptr;
int                   BpfSockmapManager::sockmap_fd_ = -1;
int                   BpfSockmapManager::pair_fd_    = -1;
int                   BpfSockmapManager::stats_fd_   = -1;
int                   BpfSockmapManager::ringbuf_fd_ = -1;
bool                  BpfSockmapManager::available_  = false;
std::atomic<uint32_t> BpfSockmapManager::next_index_{0};
std::atomic<uint64_t> BpfSockmapManager::active_tunnels_{0};
std::atomic<uint64_t> BpfSockmapManager::total_tunnels_{0};
std::atomic<uint64_t> BpfSockmapManager::total_bytes_{0};
std::atomic<uint64_t> BpfSockmapManager::fallback_count_{0};
std::atomic<uint64_t> BpfSockmapManager::error_count_{0};

namespace
{
/**
 * Check that the kernel version is at least 5.4 (sockmap maturity).
 */
bool
check_kernel_version()
{
  struct utsname buf;
  if (uname(&buf) != 0) {
    Warning("BPF sockmap: uname() failed: %s", strerror(errno));
    return false;
  }

  int major = 0, minor = 0;
  if (sscanf(buf.release, "%d.%d", &major, &minor) < 2) {
    Warning("BPF sockmap: failed to parse kernel version '%s'", buf.release);
    return false;
  }

  if (major < 5 || (major == 5 && minor < 4)) {
    Note("BPF sockmap: kernel %d.%d is below minimum 5.4, disabling", major, minor);
    return false;
  }

  Dbg(dbg_ctl_bpf, "kernel version %d.%d meets minimum requirement", major, minor);
  return true;
}

/**
 * Get the socket cookie for an FD.
 */
uint64_t
get_socket_cookie(int fd)
{
  uint64_t  cookie = 0;
  socklen_t optlen = sizeof(cookie);
  if (getsockopt(fd, SOL_SOCKET, SO_COOKIE, &cookie, &optlen) != 0) {
    Warning("BPF sockmap: getsockopt(SO_COOKIE) failed for fd %d: %s", fd, strerror(errno));
    return 0;
  }
  return cookie;
}

} // anonymous namespace

bool
BpfSockmapManager::init()
{
  if (!check_kernel_version()) {
    return false;
  }

  // Open and load BPF programs via skeleton
  struct sockmap_tunnel_bpf *skel = sockmap_tunnel_bpf__open_and_load();
  if (!skel) {
    Warning("BPF sockmap: failed to open/load BPF programs: %s", strerror(errno));
    return false;
  }

  // Store the bpf_object for later cleanup
  obj_ = skel->obj;

  // Get map FDs from the skeleton
  sockmap_fd_ = bpf_map__fd(skel->maps.sockmap);
  pair_fd_    = bpf_map__fd(skel->maps.sock_pair);
  stats_fd_   = bpf_map__fd(skel->maps.sock_stats);
  ringbuf_fd_ = bpf_map__fd(skel->maps.notify_ringbuf);

  if (sockmap_fd_ < 0 || pair_fd_ < 0 || stats_fd_ < 0 || ringbuf_fd_ < 0) {
    Warning("BPF sockmap: failed to get map FDs");
    sockmap_tunnel_bpf__destroy(skel);
    obj_ = nullptr;
    return false;
  }

  // Attach stream_parser and stream_verdict to the sockmap
  int parser_fd  = bpf_program__fd(skel->progs.bpf_stream_parser);
  int verdict_fd = bpf_program__fd(skel->progs.bpf_stream_verdict);

  if (bpf_prog_attach(parser_fd, sockmap_fd_, BPF_SK_SKB_STREAM_PARSER, 0) != 0) {
    Warning("BPF sockmap: failed to attach stream_parser: %s", strerror(errno));
    sockmap_tunnel_bpf__destroy(skel);
    obj_ = nullptr;
    return false;
  }

  if (bpf_prog_attach(verdict_fd, sockmap_fd_, BPF_SK_SKB_STREAM_VERDICT, 0) != 0) {
    Warning("BPF sockmap: failed to attach stream_verdict: %s", strerror(errno));
    bpf_prog_detach(sockmap_fd_, BPF_SK_SKB_STREAM_PARSER);
    sockmap_tunnel_bpf__destroy(skel);
    obj_ = nullptr;
    return false;
  }

  // Attach sock_ops to the root cgroup
  int sockops_fd = bpf_program__fd(skel->progs.bpf_sock_ops);
  int cgroup_fd  = open("/sys/fs/cgroup", O_RDONLY);
  if (cgroup_fd < 0) {
    // Try cgroupv1 fallback
    cgroup_fd = open("/sys/fs/cgroup/unified", O_RDONLY);
  }

  if (cgroup_fd >= 0) {
    if (bpf_prog_attach(sockops_fd, cgroup_fd, BPF_CGROUP_SOCK_OPS, 0) != 0) {
      Warning("BPF sockmap: failed to attach sock_ops to cgroup: %s", strerror(errno));
      // Non-fatal: we lose close detection but can still do forwarding
      // BpfTunnelPoller liveness checks will handle cleanup
    }
    close(cgroup_fd);
  } else {
    Warning("BPF sockmap: failed to open cgroup fd: %s (close detection disabled)", strerror(errno));
  }

  available_ = true;
  Note("BPF sockmap tunnel acceleration initialized successfully");

  return true;
}

void
BpfSockmapManager::shutdown()
{
  if (!available_) {
    return;
  }

  available_ = false;

  // Detach programs
  if (sockmap_fd_ >= 0) {
    bpf_prog_detach(sockmap_fd_, BPF_SK_SKB_STREAM_PARSER);
    bpf_prog_detach(sockmap_fd_, BPF_SK_SKB_STREAM_VERDICT);
  }

  // The skeleton destroy closes all FDs and frees the object
  if (obj_) {
    bpf_object__close(obj_);
    obj_ = nullptr;
  }

  sockmap_fd_ = -1;
  pair_fd_    = -1;
  stats_fd_   = -1;
  ringbuf_fd_ = -1;

  Note("BPF sockmap tunnel acceleration shut down");
}

bool
BpfSockmapManager::is_available()
{
  return available_;
}

bool
BpfSockmapManager::insert_tunnel(int client_fd, int origin_fd, uint64_t tunnel_id)
{
  if (!available_) {
    return false;
  }

  uint64_t client_cookie = get_socket_cookie(client_fd);
  uint64_t origin_cookie = get_socket_cookie(origin_fd);
  if (client_cookie == 0 || origin_cookie == 0) {
    Note("BPF insert: cookie failed client=%" PRIu64 " origin=%" PRIu64, client_cookie, origin_cookie);
    error_count_.fetch_add(1, std::memory_order_relaxed);
    return false;
  }

  // Allocate two sockmap indices
  uint32_t client_idx = next_index_.fetch_add(2, std::memory_order_relaxed);
  uint32_t origin_idx = client_idx + 1;

  // Wrap around if we hit the max
  if (origin_idx >= SOCKMAP_MAX_ENTRIES) {
    next_index_.store(0, std::memory_order_relaxed);
    client_idx = next_index_.fetch_add(2, std::memory_order_relaxed);
    origin_idx = client_idx + 1;
  }

  Note("BPF insert: cookies client=%" PRIu64 " origin=%" PRIu64 " indices=%u/%u sockmap_fd=%d", client_cookie, origin_cookie,
       client_idx, origin_idx, sockmap_fd_);

  // Insert both sockets into sockmap
  if (bpf_map_update_elem(sockmap_fd_, &client_idx, &client_fd, BPF_ANY) != 0) {
    Note("BPF sockmap insert failed for client fd %d idx %u: %s (errno %d)", client_fd, client_idx, strerror(errno), errno);
    error_count_.fetch_add(1, std::memory_order_relaxed);
    return false;
  }

  if (bpf_map_update_elem(sockmap_fd_, &origin_idx, &origin_fd, BPF_ANY) != 0) {
    Note("BPF sockmap insert failed for origin fd %d idx %u: %s (errno %d)", origin_fd, origin_idx, strerror(errno), errno);
    bpf_map_delete_elem(sockmap_fd_, &client_idx);
    error_count_.fetch_add(1, std::memory_order_relaxed);
    return false;
  }

  // Set up bidirectional pairing: client cookie -> origin index, origin cookie -> client index
  if (bpf_map_update_elem(pair_fd_, &client_cookie, &origin_idx, BPF_ANY) != 0) {
    Note("BPF sock_pair insert failed for client cookie %" PRIu64 ": %s (errno %d)", client_cookie, strerror(errno), errno);
    bpf_map_delete_elem(sockmap_fd_, &client_idx);
    bpf_map_delete_elem(sockmap_fd_, &origin_idx);
    error_count_.fetch_add(1, std::memory_order_relaxed);
    return false;
  }

  if (bpf_map_update_elem(pair_fd_, &origin_cookie, &client_idx, BPF_ANY) != 0) {
    Note("BPF sock_pair insert failed for origin cookie %" PRIu64 ": %s (errno %d)", origin_cookie, strerror(errno), errno);
    bpf_map_delete_elem(pair_fd_, &client_cookie);
    bpf_map_delete_elem(sockmap_fd_, &client_idx);
    bpf_map_delete_elem(sockmap_fd_, &origin_idx);
    error_count_.fetch_add(1, std::memory_order_relaxed);
    return false;
  }

  // Initialize stats entries
  struct tunnel_stats zero_stats = {0, 0};
  bpf_map_update_elem(stats_fd_, &client_cookie, &zero_stats, BPF_ANY);
  bpf_map_update_elem(stats_fd_, &origin_cookie, &zero_stats, BPF_ANY);

  // Register in the tunnel registry for cookie -> tunnel_id mapping
  BpfTunnelRegistry::register_tunnel(tunnel_id, client_fd, origin_fd, client_cookie, origin_cookie, client_idx, origin_idx);

  active_tunnels_.fetch_add(1, std::memory_order_relaxed);
  total_tunnels_.fetch_add(1, std::memory_order_relaxed);

  Note("BPF tunnel %" PRIu64 " inserted OK: client(fd=%d,cookie=%" PRIu64 ",idx=%u) origin(fd=%d,cookie=%" PRIu64 ",idx=%u)",
       tunnel_id, client_fd, client_cookie, client_idx, origin_fd, origin_cookie, origin_idx);

  return true;
}

void
BpfSockmapManager::remove_tunnel(uint64_t tunnel_id)
{
  if (!available_) {
    return;
  }

  auto info = BpfTunnelRegistry::lookup_by_tunnel_id(tunnel_id);
  if (!info) {
    Dbg(dbg_ctl_bpf, "remove_tunnel: tunnel %" PRIu64 " not found in registry", tunnel_id);
    return;
  }

  // Accumulate final stats before removing
  struct tunnel_stats client_stats = {0, 0};
  struct tunnel_stats origin_stats = {0, 0};
  bpf_map_lookup_elem(stats_fd_, &info->client_cookie, &client_stats);
  bpf_map_lookup_elem(stats_fd_, &info->origin_cookie, &origin_stats);
  total_bytes_.fetch_add(client_stats.bytes + origin_stats.bytes, std::memory_order_relaxed);

  // Remove from all BPF maps (order: pair first to stop redirects, then sockmap, then stats)
  bpf_map_delete_elem(pair_fd_, &info->client_cookie);
  bpf_map_delete_elem(pair_fd_, &info->origin_cookie);
  bpf_map_delete_elem(sockmap_fd_, &info->client_idx);
  bpf_map_delete_elem(sockmap_fd_, &info->origin_idx);
  bpf_map_delete_elem(stats_fd_, &info->client_cookie);
  bpf_map_delete_elem(stats_fd_, &info->origin_cookie);

  BpfTunnelRegistry::unregister_tunnel(tunnel_id);

  active_tunnels_.fetch_sub(1, std::memory_order_relaxed);

  Dbg(dbg_ctl_bpf, "tunnel %" PRIu64 " removed (%" PRIu64 " bytes forwarded)", tunnel_id,
      static_cast<uint64_t>(client_stats.bytes + origin_stats.bytes));
}

BpfSockmapManager::AggregateStats
BpfSockmapManager::get_aggregate_stats()
{
  return {
    active_tunnels_.load(std::memory_order_relaxed), total_tunnels_.load(std::memory_order_relaxed),
    total_bytes_.load(std::memory_order_relaxed),    fallback_count_.load(std::memory_order_relaxed),
    error_count_.load(std::memory_order_relaxed),
  };
}

int
BpfSockmapManager::get_ringbuf_fd()
{
  return ringbuf_fd_;
}

int
BpfSockmapManager::get_sockmap_fd()
{
  return sockmap_fd_;
}

int
BpfSockmapManager::get_stats_fd()
{
  return stats_fd_;
}

int
BpfSockmapManager::get_pair_fd()
{
  return pair_fd_;
}

#endif /* TS_USE_BPF_SOCKMAP */
