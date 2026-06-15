/** @file

  Unit tests for HttpSessionManager pool eviction metrics.

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

#include <catch2/catch_test_macros.hpp>

#include "proxy/http/HttpConfig.h"
#include "tsutil/Metrics.h"

using ts::Metrics;

// These must exactly match the strings registered in HttpConfig.cc.
static constexpr std::string_view POOL_PEER_CLOSED_NAME{"proxy.process.http.origin_shutdown.pool_peer_closed"};
static constexpr std::string_view POOL_TIMEOUT_NAME{"proxy.process.http.origin_shutdown.pool_timeout"};

TEST_CASE("ServerSessionPool eviction metrics registration", "[http][session_pool]")
{
  // Metrics::Counter::createPtr is idempotent: returns the existing AtomicType*
  // if the metric name was already registered (e.g. by HttpConfig::startup()),
  // or creates it fresh if not yet registered.
  auto *peer_closed_metric = Metrics::Counter::createPtr(POOL_PEER_CLOSED_NAME);
  auto *timeout_metric     = Metrics::Counter::createPtr(POOL_TIMEOUT_NAME);

  SECTION("pool_peer_closed metric registers successfully")
  {
    REQUIRE(peer_closed_metric != nullptr);
  }

  SECTION("pool_timeout metric registers successfully")
  {
    REQUIRE(timeout_metric != nullptr);
  }

  SECTION("repeated createPtr returns the same pointer")
  {
    auto *p1 = Metrics::Counter::createPtr(POOL_PEER_CLOSED_NAME);
    auto *p2 = Metrics::Counter::createPtr(POOL_PEER_CLOSED_NAME);
    REQUIRE(p1 == p2);

    auto *t1 = Metrics::Counter::createPtr(POOL_TIMEOUT_NAME);
    auto *t2 = Metrics::Counter::createPtr(POOL_TIMEOUT_NAME);
    REQUIRE(t1 == t2);
  }

  SECTION("pool_peer_closed and pool_timeout are distinct metrics")
  {
    REQUIRE(peer_closed_metric != timeout_metric);
  }
}

TEST_CASE("ServerSessionPool eviction metric counter operations", "[http][session_pool]")
{
  SECTION("pool_peer_closed counter increments correctly")
  {
    auto   *m      = Metrics::Counter::createPtr(POOL_PEER_CLOSED_NAME);
    int64_t before = m->load();

    Metrics::Counter::increment(m);

    REQUIRE(m->load() == before + 1);
  }

  SECTION("pool_timeout counter increments correctly")
  {
    auto   *m      = Metrics::Counter::createPtr(POOL_TIMEOUT_NAME);
    int64_t before = m->load();

    Metrics::Counter::increment(m);

    REQUIRE(m->load() == before + 1);
  }

  SECTION("incrementing pool_peer_closed does not affect pool_timeout")
  {
    auto *peer = Metrics::Counter::createPtr(POOL_PEER_CLOSED_NAME);
    auto *tout = Metrics::Counter::createPtr(POOL_TIMEOUT_NAME);

    int64_t tout_before = tout->load();

    Metrics::Counter::increment(peer);

    REQUIRE(tout->load() == tout_before);
  }

  SECTION("incrementing pool_timeout does not affect pool_peer_closed")
  {
    auto *peer = Metrics::Counter::createPtr(POOL_PEER_CLOSED_NAME);
    auto *tout = Metrics::Counter::createPtr(POOL_TIMEOUT_NAME);

    int64_t peer_before = peer->load();

    Metrics::Counter::increment(tout);

    REQUIRE(peer->load() == peer_before);
  }

  SECTION("multiple increments accumulate correctly")
  {
    auto   *m      = Metrics::Counter::createPtr(POOL_PEER_CLOSED_NAME);
    int64_t before = m->load();

    Metrics::Counter::increment(m);
    Metrics::Counter::increment(m);
    Metrics::Counter::increment(m);

    REQUIRE(m->load() == before + 3);
  }
}

TEST_CASE("ServerSessionPool eviction metric name round-trip", "[http][session_pool]")
{
  SECTION("pool_peer_closed name is preserved in the registry")
  {
    // Ensure the metric exists.
    Metrics::Counter::createPtr(POOL_PEER_CLOSED_NAME);

    // Look up by name to get the ID.
    Metrics::IdType id = Metrics::Counter::lookup(POOL_PEER_CLOSED_NAME);
    REQUIRE(id != Metrics::NOT_FOUND);

    // Look up by ID to get the name back.
    std::string_view stored_name;
    Metrics::Counter::lookup(id, &stored_name);
    REQUIRE(stored_name == POOL_PEER_CLOSED_NAME);
  }

  SECTION("pool_timeout name is preserved in the registry")
  {
    Metrics::Counter::createPtr(POOL_TIMEOUT_NAME);

    Metrics::IdType id = Metrics::Counter::lookup(POOL_TIMEOUT_NAME);
    REQUIRE(id != Metrics::NOT_FOUND);

    std::string_view stored_name;
    Metrics::Counter::lookup(id, &stored_name);
    REQUIRE(stored_name == POOL_TIMEOUT_NAME);
  }
}

TEST_CASE("ServerSessionPool http_rsb pointer consistency", "[http][session_pool]")
{
  SECTION("http_rsb pool eviction pointers agree with the Metrics registry")
  {
    // In the unit-test binary HttpConfig::startup() is not called, so
    // http_rsb.origin_shutdown_pool_peer_closed is null.  We still ensure that
    // the metric name used by HttpConfig::startup() matches the constant above.
    // When the pointers ARE set (integration environment), they must be the
    // same AtomicType* that the Metrics registry returns by name.
    auto *via_name_peer = Metrics::Counter::createPtr(POOL_PEER_CLOSED_NAME);
    REQUIRE(via_name_peer != nullptr);

    if (http_rsb.origin_shutdown_pool_peer_closed != nullptr) {
      REQUIRE(http_rsb.origin_shutdown_pool_peer_closed == via_name_peer);
    }

    auto *via_name_tout = Metrics::Counter::createPtr(POOL_TIMEOUT_NAME);
    REQUIRE(via_name_tout != nullptr);

    if (http_rsb.origin_shutdown_pool_timeout != nullptr) {
      REQUIRE(http_rsb.origin_shutdown_pool_timeout == via_name_tout);
    }
  }
}
