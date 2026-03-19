/** @file

  BPF programs for sockmap-based blind tunnel acceleration.

  Three programs work together to redirect TCP data between paired sockets
  entirely in kernel space, eliminating userspace copies for blind tunnels.

  - stream_parser:  Parses incoming data length (pass-through for blind tunnels)
  - stream_verdict: Looks up peer socket and redirects via sockmap
  - sock_ops:       Detects socket close events and notifies userspace

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

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "sockmap_tunnel.h"

char LICENSE[] SEC("license") = "Apache-2.0";

/*
 * Map definitions
 */

/* SOCKMAP: holds sockets eligible for redirect. Key is a u32 index. */
struct {
  __uint(type, BPF_MAP_TYPE_SOCKMAP);
  __uint(max_entries, SOCKMAP_MAX_ENTRIES);
  __type(key, __u32);
  __type(value, __u32); /* socket fd */
} sockmap SEC(".maps");

/*
 * HASH: maps a socket cookie to its peer's sockmap index.
 * When socket A receives data, we look up A's cookie to find B's index,
 * then redirect the skb to B via the sockmap.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, SOCKMAP_MAX_ENTRIES);
  __type(key, __u64);   /* socket cookie */
  __type(value, __u32); /* peer's sockmap index */
} sock_pair SEC(".maps");

/* PERCPU_HASH: per-socket byte/packet counters. Per-CPU to avoid atomics. */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __uint(max_entries, SOCKMAP_MAX_ENTRIES);
  __type(key, __u64); /* socket cookie */
  __type(value, struct tunnel_stats);
} sock_stats SEC(".maps");

/* RINGBUF: kernel -> userspace close/error notifications */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, RING_BUF_SIZE);
} notify_ringbuf SEC(".maps");

/*
 * stream_parser: determines the length of each message to pass to stream_verdict.
 *
 * For blind tunnels, we always forward the entire available buffer — there's
 * no application-layer framing to parse. Return skb->len to pass the full
 * buffer to the verdict program.
 */
SEC("sk_skb/stream_parser")
int
bpf_stream_parser(struct __sk_buff *skb)
{
  return skb->len;
}

/*
 * stream_verdict: decides where to redirect each skb.
 *
 * Looks up the current socket's cookie in sock_pair to find the peer's
 * sockmap index, updates per-socket stats, and redirects the skb to the
 * peer socket. If the socket isn't in our map (shouldn't happen for
 * managed tunnels), returns SK_PASS to let data flow to userspace.
 */
SEC("sk_skb/stream_verdict")
int
bpf_stream_verdict(struct __sk_buff *skb)
{
  __u64 cookie = bpf_get_socket_cookie(skb);

  __u32 *peer_idx = bpf_map_lookup_elem(&sock_pair, &cookie);
  if (!peer_idx) {
    return SK_PASS; /* not our socket, pass to userspace */
  }

  /* Update per-socket stats */
  struct tunnel_stats *stats = bpf_map_lookup_elem(&sock_stats, &cookie);
  if (stats) {
    __sync_fetch_and_add(&stats->bytes, skb->len);
    __sync_fetch_and_add(&stats->packets, 1);
  }

  return bpf_sk_redirect_map(skb, &sockmap, *peer_idx, BPF_F_INGRESS);
}

/*
 * sock_ops: monitors socket state transitions for managed sockets.
 *
 * When a socket enters a closing state (CLOSE_WAIT, FIN_WAIT1, CLOSE),
 * we send a notification to userspace via the ring buffer so ATS can
 * clean up the tunnel pair and proceed with normal connection teardown.
 */
SEC("sockops")
int
bpf_sock_ops(struct bpf_sock_ops *skops)
{
  if (skops->op != BPF_SOCK_OPS_STATE_CB) {
    return 0;
  }

  /* args[1] is the new TCP state */
  int new_state = skops->args[1];

  if (new_state != BPF_TCP_CLOSE_WAIT && new_state != BPF_TCP_FIN_WAIT1 && new_state != BPF_TCP_CLOSE) {
    return 0;
  }

  /* Check if this socket is one we're managing */
  __u64  cookie   = bpf_get_socket_cookie(skops);
  __u32 *peer_idx = bpf_map_lookup_elem(&sock_pair, &cookie);
  if (!peer_idx) {
    return 0; /* not our socket */
  }

  /* Notify userspace of the close event */
  struct tunnel_event *evt = bpf_ringbuf_reserve(&notify_ringbuf, sizeof(*evt), 0);
  if (evt) {
    evt->cookie = cookie;
    evt->event  = TUNNEL_EVENT_CLOSE;
    evt->pad    = 0;
    bpf_ringbuf_submit(evt, 0);
  }

  return 0;
}
