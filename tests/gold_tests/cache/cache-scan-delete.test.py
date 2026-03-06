'''
Test cache scan with delete across multiple volumes (#12583).

When TSCacheScan returns DELETE_ALL_ALTERNATES for objects, the internal
scanObject() calls cacheProcessor.remove() which recomputes the stripe via
key_to_stripe(). With multiple volumes, this can return a different stripe
than the one being scanned, causing the remove to fail and scanRemoveDone()
to loop back to scanObject() on the same object infinitely.

This test:
  1. Configures ATS with 9 cache volumes (matching the reporter's setup)
  2. Populates the cache with objects via normal HTTP requests
  3. Waits for cache writes to flush
  4. Triggers a TSCacheScan that deletes all objects via a header trigger
  5. Polls for a marker file to verify the scan completed
'''
#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information
#  regarding copyright ownership.  The ASF licenses this file
#  to you under the Apache License, Version 2.0 (the
#  "License"); you may not use this file except in compliance
#  with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import os

Test.Summary = 'Test cache scan delete with multiple volumes (#12583)'

server = Test.MakeOriginServer("server")

HOSTS = ["www.example.com", "cdn.example.com", "api.example.com"]
OBJECTS_PER_HOST = 100
NUM_OBJECTS = len(HOSTS) * OBJECTS_PER_HOST
for host in HOSTS:
    for i in range(OBJECTS_PER_HOST):
        body = f"cached-object-{host}-{i}-" + ("x" * 131072)
        request_header = {"headers": f"GET /obj/{i} HTTP/1.1\r\nHost: {host}\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
        response_header = {
            "headers": f"HTTP/1.1 200 OK\r\nCache-Control: max-age=3600\r\nContent-Length: {len(body)}\r\n\r\n",
            "timestamp": "1469733493.993",
            "body": body
        }
        server.addResponse("sessionlog.json", request_header, response_header)

ts = Test.MakeATSProcess("ts")

marker_file = os.path.join(Test.RunDirectory, "scan_done.txt")

# Configure 9 volumes on a single storage file (matching reporter's setup from #12583)
ts.Disk.storage_config.AddLine("storage 2G")
ts.Disk.volume_config.AddLines(
    [
        "volume=1 scheme=http size=11%",
        "volume=2 scheme=http size=11%",
        "volume=3 scheme=http size=11%",
        "volume=4 scheme=http size=11%",
        "volume=5 scheme=http size=11%",
        "volume=6 scheme=http size=11%",
        "volume=7 scheme=http size=11%",
        "volume=8 scheme=http size=11%",
        "volume=9 scheme=http size=12%",
    ])

# Load the cache_scan_delete test plugin with marker file path
plugin_path = os.path.join(Test.Variables.AtsBuildGoldTestsDir, 'pluginTest', 'cache_scan_delete', '.libs', 'cache_scan_delete.so')
ts.Setup.Copy(plugin_path, ts.Env['PROXY_CONFIG_PLUGIN_PLUGIN_DIR'])
ts.Disk.plugin_config.AddLine(f"cache_scan_delete.so {marker_file}")

# Map hostnames to specific volumes to trigger the stripe mismatch bug.
# When scanObject() extracts the hostname from a cached object and passes it
# to cacheProcessor.remove(), key_to_stripe() uses the hosting.config mapping
# which can return a different stripe than the one being scanned.
ts.Disk.hosting_config.AddLines(
    [
        "hostname=www.example.com volume=1,2,3",
        "hostname=cdn.example.com volume=4,5,6",
        "hostname=api.example.com volume=7,8,9",
    ])

ts.Disk.remap_config.AddLine(f"map / http://127.0.0.1:{server.Variables.Port}/")

ts.Disk.records_config.update(
    {
        'proxy.config.diags.debug.enabled': 1,
        'proxy.config.diags.debug.tags': 'cache_scan_delete|cache_scan',
        'proxy.config.http.wait_for_cache': 2,
    })

# Test Run 1: Populate the cache with objects
tr1 = Test.AddTestRun("Populate cache")
tr1.Processes.Default.StartBefore(server)
tr1.Processes.Default.StartBefore(ts)
tr1.Processes.Default.ReturnCode = 0
curl_cmds = ' && '.join(
    f'curl -s -o /dev/null -w "%{{http_code}}\\n" http://127.0.0.1:{ts.Variables.port}/obj/{i} -H "Host: {host}"' for host in HOSTS
    for i in range(OBJECTS_PER_HOST))
tr1.Processes.Default.Command = curl_cmds
tr1.StillRunningAfter = ts

# Test Run 2: Wait for cache writes to flush, then trigger scan-delete.
tr2 = Test.AddTestRun("Trigger scan-delete")
tr2.Processes.Default.ReturnCode = 0
tr2.Processes.Default.Command = f'sleep 5 && curl -s -o /dev/null http://127.0.0.1:{ts.Variables.port}/obj/0 -H "Host: www.example.com" -H "X-Scan-Delete: start" && sleep 2'
tr2.StillRunningAfter = ts

# Test Run 3: Poll for the marker file.
# Write a Python poll script to avoid shell variable interpolation issues
# with the autest template engine.
poll_script = os.path.join(Test.RunDirectory, "poll_marker.py")
with open(poll_script, 'w') as f:
    f.write(
        f'''import time, os, sys
for _ in range(30):
    if os.path.exists("{marker_file}"):
        with open("{marker_file}") as mf:
            print(mf.read(), end="")
        sys.exit(0)
    time.sleep(1)
print("TIMEOUT: marker file never appeared")
sys.exit(1)
''')

tr3 = Test.AddTestRun("Wait for scan completion")
tr3.Processes.Default.ReturnCode = 0
tr3.Processes.Default.Command = f'python3 {poll_script}'
tr3.Processes.Default.Streams.stdout = Testers.ContainsExpression("scan_complete", "scan should complete successfully")
tr3.StillRunningAfter = ts
