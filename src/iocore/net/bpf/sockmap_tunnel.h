/** @file

  Shared definitions between BPF programs and userspace for sockmap tunnel acceleration.

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

#ifdef __cplusplus
#include <cstdint>
#else
#include "vmlinux.h"
#endif

/* Ring buffer notification events */
enum tunnel_event_type {
  TUNNEL_EVENT_CLOSE = 1, /* One side of the tunnel closed */
  TUNNEL_EVENT_ERROR = 2, /* BPF redirect error */
};

/* Ring buffer event structure - sent from BPF to userspace */
struct tunnel_event {
  __u64 cookie; /* Socket cookie of the socket that triggered the event */
  __u32 event;  /* tunnel_event_type */
  __u32 pad;    /* Alignment padding */
};

/* Per-socket stats maintained in BPF map (PERCPU) */
struct tunnel_stats {
  __u64 bytes;   /* Total bytes forwarded */
  __u64 packets; /* Total packets redirected */
};

/* Sockmap max entries - sized to max_connections * 2 */
#define SOCKMAP_MAX_ENTRIES (1 << 16) /* 65536 entries */
#define RING_BUF_SIZE       (1 << 18) /* 256KB ring buffer */
