.. Licensed to the Apache Software Foundation (ASF) under one
   or more contributor license agreements.  See the NOTICE file
   distributed with this work for additional information
   regarding copyright ownership.  The ASF licenses this file
   to you under the Apache License, Version 2.0 (the
   "License"); you may not use this file except in compliance
   with the License.  You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing,
   software distributed under the License is distributed on an
   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
   KIND, either express or implied.  See the License for the
   specific language governing permissions and limitations
   under the License.

.. include:: ../../common.defs

.. _admin-plugins-dashboard:

Dashboard Plugin
****************

This experimental remap plugin serves a real-time web dashboard showing |TS|
statistics with live-updating charts and graphs. It uses server intercept to
serve two endpoints:

- The base URL (e.g., ``/_dashboard/``) serves the HTML dashboard page
- ``/_dashboard/__api/stats`` serves a JSON API endpoint with all the stats

Enabling the Dashboard
======================

To use this plugin, add a mapping to the :file:`remap.config` file::

    map /_dashboard/ http://localhost @plugin=dashboard.so

After starting Traffic Server, the dashboard is available at::

    http://host:port/_dashboard/

where host and port is the hostname/IP and port number of |TS|.

This will expose the dashboard to anyone who could access the |TS| instance.
It is recommended you use one of the ACL features in |TS|. For example::

    map /_dashboard/ \
        http://127.0.0.1 \
        @plugin=dashboard.so \
        @src_ip=127.0.0.1 @src_ip=::1 \
        @src_ip=10.0.0.0-10.255.255.255 \
        @action=allow

Dashboard Features
==================

- **Live-updating sparkline charts** for throughput, bandwidth, cache hit rate,
  and latency
- **30+ configurable widgets** organized into categories: Summary, Traffic,
  Connections, Cache, Network, System
- **Drag-and-drop widget reordering**
- **Widget size options**: half, standard, medium, tall
- **Settings panel** to show/hide widgets
- **Layout preferences** saved in browser cookies
- **Dark theme**, responsive design
- **No external dependencies** — all HTML/CSS/JS is self-contained in the plugin

Statistics Shown
================

The dashboard displays the following statistics:

- **Cache**: disk/RAM usage, hit ratios, operations, stripes, directory entries
- **HTTP**: requests, response codes (1xx–5xx), methods (GET/POST/etc), tunnels
- **Connections**: client (total/active/idle), server, cache, origin
- **Bandwidth**: client/origin bytes, network I/O
- **DNS/HostDB**: lookups and hit rates
- **SSL/TLS**: handshakes, session cache, certificates
- **HTTP/2**: connections, streams, errors
- **Errors**: client aborts, connect failures, cache errors
- **System**: memory (RSS), event loop, logging, milestones

Plugin Options
==============

The plugin takes no arguments. The HTML dashboard is embedded directly in the
plugin.
