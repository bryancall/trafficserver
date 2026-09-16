/** @file

  Unit tests for the traffic_top stats collector.

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
#include <catch2/catch_approx.hpp>

#include <map>
#include <string>
#include <vector>

#include "../stats.h"

namespace
{

shared::rpc::RecordLookUpResponse::RecordParamInfo
make_record(std::string name, std::string value)
{
  shared::rpc::RecordLookUpResponse::RecordParamInfo info{};

  info.name         = std::move(name);
  info.currentValue = std::move(value);
  return info;
}

/// Stats with the RPC call replaced by a canned response, so a poll can be made to succeed or fail
/// on demand without a running server.
class TestStats : public Stats
{
public:
  using Stats::fill_stats;

  bool                               fail_fetch{false};
  std::map<std::string, std::string> canned;

protected:
  std::string
  fetch_records(shared::rpc::RecordLookupRequest const & /* request */,
                shared::rpc::RecordLookUpResponse &records) noexcept override
  {
    if (fail_fetch) {
      return "simulated fetch failure";
    }
    for (auto const &[name, value] : canned) {
      records.recordList.push_back(make_record(name, value));
    }
    return {};
  }
};

} // namespace

TEST_CASE("One unknown record name does not discard the rest of the response", "[traffic_top]")
{
  shared::rpc::RecordLookUpResponse response;

  response.recordList.push_back(make_record("proxy.process.http.incoming_requests", "175"));
  response.recordList.push_back(make_record("proxy.process.http.cache_lookups", "42"));
  response.errorList.push_back({"RECORD_NOT_FOUND", "proxy.process.not.a.real.metric", "Record not found"});

  std::map<std::string, std::string> stats;
  std::vector<std::string>           unknown;

  CHECK(TestStats::fill_stats(response, &stats, &unknown).empty());

  CHECK(stats.size() == 2);
  CHECK(stats["proxy.process.http.incoming_requests"] == "175");
  CHECK(stats["proxy.process.http.cache_lookups"] == "42");

  REQUIRE(unknown.size() == 1);
  CHECK(unknown[0] == "proxy.process.not.a.real.metric");
}

TEST_CASE("A response with nothing usable in it is still an error", "[traffic_top]")
{
  shared::rpc::RecordLookUpResponse response;

  response.errorList.push_back({"RECORD_NOT_FOUND", "proxy.process.not.a.real.metric", "Record not found"});

  std::map<std::string, std::string> stats;
  std::vector<std::string>           unknown;

  CHECK_FALSE(TestStats::fill_stats(response, &stats, &unknown).empty());
  CHECK(stats.empty());
}

TEST_CASE("A dropped poll does not zero the previous sample", "[traffic_top]")
{
  TestStats stats;

  CHECK_FALSE(stats.haveSample());

  stats.canned["proxy.process.http.incoming_requests"] = "1000";
  stats.canned["proxy.process.http.cache_lookups"]     = "2000";
  REQUIRE(stats.getStats());
  CHECK(stats.haveSample());

  std::string raw;
  stats.getStat("client_req", raw);
  CHECK(raw == "1000");

  // Second poll is dropped. The sample we already have is the only truth we have, so it must survive.
  stats.fail_fetch = true;
  REQUIRE_FALSE(stats.getStats());

  stats.getStat("client_req", raw);
  CHECK(raw == "1000");

  double rate = 0;
  stats.getStat("client_req", rate);
  CHECK(rate >= 0);

  // Third poll lands. Both counters advanced by exactly 100 over the same interval, so their rates
  // must agree. Treating the dropped poll as a sample of zero makes the deltas 1100 and 2100 instead.
  stats.fail_fetch                                     = false;
  stats.canned["proxy.process.http.incoming_requests"] = "1100";
  stats.canned["proxy.process.http.cache_lookups"]     = "2100";
  REQUIRE(stats.getStats());

  double client_req_rate = 0;
  double lookups_rate    = 0;
  stats.getStat("client_req", client_req_rate);
  stats.getStat("lookups", lookups_rate);

  CHECK(client_req_rate > 0);
  CHECK(client_req_rate == Catch::Approx(lookups_rate));
}
