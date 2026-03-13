/** @file

  ATS Dashboard - Real-time web dashboard for Apache Traffic Server

  Remap plugin that serves a live-updating HTML dashboard showing
  cache health, connections, bandwidth, hit ratios, and other ATS
  internal statistics via server intercept.

  Endpoints:
    /_dashboard/           -> HTML dashboard page
    /_dashboard/__api/stats -> JSON stats for live polling

  Based on the http_stats.cc experimental plugin pattern.
*/

#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <string>
#include <ctime>
#include <fstream>

#include "ts/ts.h"
#include "ts/remap.h"

constexpr char PLUGIN[] = "dashboard";

static DbgCtl dbg_ctl{PLUGIN};

#define VDEBUG(fmt, ...) Dbg(dbg_ctl, fmt, ##__VA_ARGS__)

#if DEBUG
#define VERROR(fmt, ...) Dbg(dbg_ctl, fmt, ##__VA_ARGS__)
#else
#define VERROR(fmt, ...) TSError("[%s] %s: " fmt, PLUGIN, __FUNCTION__, ##__VA_ARGS__)
#endif

#define VIODEBUG(vio, fmt, ...)                                                                                              \
  VDEBUG("vio=%p vio.cont=%p, vio.cont.data=%p, vio.vc=%p " fmt, (vio), TSVIOContGet(vio), TSContDataGet(TSVIOContGet(vio)), \
         TSVIOVConnGet(vio), ##__VA_ARGS__)

static int    StatCountBytes     = -1;
static int    StatCountResponses = -1;
static time_t PluginStartTime    = 0;

static int DashboardInterceptHook(TSCont contp, TSEvent event, void *edata);

enum class RequestType { HTML, JSON };

union argument_type {
  void     *ptr;
  intptr_t  ecode;
  TSVConn   vc;
  TSVIO     vio;
  TSHttpTxn txn;

  argument_type(void *_p) : ptr(_p) {}
};

struct IOChannel {
  TSVIO            vio = nullptr;
  TSIOBuffer       iobuf;
  TSIOBufferReader reader;

  IOChannel() : iobuf(TSIOBufferSizedCreate(TS_IOBUFFER_SIZE_INDEX_32K)), reader(TSIOBufferReaderAlloc(iobuf)) {}
  ~IOChannel()
  {
    if (this->reader) {
      TSIOBufferReaderFree(this->reader);
    }
    if (this->iobuf) {
      TSIOBufferDestroy(this->iobuf);
    }
  }

  void
  read(TSVConn vc, TSCont contp)
  {
    this->vio = TSVConnRead(vc, contp, this->iobuf, INT64_MAX);
  }
  void
  write(TSVConn vc, TSCont contp)
  {
    this->vio = TSVConnWrite(vc, contp, this->reader, INT64_MAX);
  }
};

struct DashboardHttpHeader {
  TSMBuffer    buffer;
  TSMLoc       header;
  TSHttpParser parser;

  DashboardHttpHeader()
  {
    this->buffer = TSMBufferCreate();
    this->header = TSHttpHdrCreate(this->buffer);
    this->parser = TSHttpParserCreate();
  }

  ~DashboardHttpHeader()
  {
    if (this->parser) {
      TSHttpParserDestroy(this->parser);
    }
    TSHttpHdrDestroy(this->buffer, this->header);
    TSHandleMLocRelease(this->buffer, TS_NULL_MLOC, this->header);
    TSMBufferDestroy(this->buffer);
  }
};

struct DashboardRequest {
  off_t               nbytes     = 0;
  unsigned            statusCode = 200;
  IOChannel           readio;
  IOChannel           writeio;
  DashboardHttpHeader rqheader;
  RequestType         request_type = RequestType::HTML;
  std::string         mimeType;
  std::string         body;

  ~DashboardRequest() = default;
};

// Forward declarations
static std::string build_stats_json();
static std::string build_dashboard_html();

static void
DashboardRequestDestroy(DashboardRequest *trq, TSVIO vio, TSCont contp)
{
  if (vio) {
    TSVConnClose(TSVIOVConnGet(vio));
  }
  TSContDestroy(contp);
  delete trq;
}

static void
HeaderFieldDateSet(const DashboardHttpHeader &http, const char *field_name, int64_t field_len, time_t value)
{
  TSMLoc field;
  TSMimeHdrFieldCreateNamed(http.buffer, http.header, field_name, field_len, &field);
  TSMimeHdrFieldValueDateSet(http.buffer, http.header, field, value);
  TSMimeHdrFieldAppend(http.buffer, http.header, field);
  TSHandleMLocRelease(http.buffer, http.header, field);
}

static void
HeaderFieldIntSet(const DashboardHttpHeader &http, const char *field_name, int64_t field_len, int64_t value)
{
  TSMLoc field;
  TSMimeHdrFieldCreateNamed(http.buffer, http.header, field_name, field_len, &field);
  TSMimeHdrFieldValueInt64Set(http.buffer, http.header, field, -1, value);
  TSMimeHdrFieldAppend(http.buffer, http.header, field);
  TSHandleMLocRelease(http.buffer, http.header, field);
}

static void
HeaderFieldStringSet(const DashboardHttpHeader &http, const char *field_name, int64_t field_len, const char *value)
{
  TSMLoc field;
  TSMimeHdrFieldCreateNamed(http.buffer, http.header, field_name, field_len, &field);
  TSMimeHdrFieldValueStringSet(http.buffer, http.header, field, -1, value, -1);
  TSMimeHdrFieldAppend(http.buffer, http.header, field);
  TSHandleMLocRelease(http.buffer, http.header, field);
}

static TSReturnCode
WriteResponseHeader(DashboardRequest *trq, TSHttpStatus status)
{
  DashboardHttpHeader response;

  if (TSHttpHdrTypeSet(response.buffer, response.header, TS_HTTP_TYPE_RESPONSE) != TS_SUCCESS) {
    return TS_ERROR;
  }
  if (TSHttpHdrVersionSet(response.buffer, response.header, TS_HTTP_VERSION(1, 1)) != TS_SUCCESS) {
    return TS_ERROR;
  }
  if (TSHttpHdrStatusSet(response.buffer, response.header, status) != TS_SUCCESS) {
    return TS_ERROR;
  }

  TSHttpHdrReasonSet(response.buffer, response.header, TSHttpHdrReasonLookup(status), -1);

  if (status == TS_HTTP_STATUS_OK) {
    HeaderFieldIntSet(response, TS_MIME_FIELD_CONTENT_LENGTH, TS_MIME_LEN_CONTENT_LENGTH, trq->nbytes);
    HeaderFieldStringSet(response, TS_MIME_FIELD_CACHE_CONTROL, TS_MIME_LEN_CACHE_CONTROL, "no-cache, no-store");
    HeaderFieldStringSet(response, TS_MIME_FIELD_CONTENT_TYPE, TS_MIME_LEN_CONTENT_TYPE, trq->mimeType.c_str());

    // CORS for API
    if (trq->request_type == RequestType::JSON) {
      HeaderFieldStringSet(response, "Access-Control-Allow-Origin", 27, "*");
    }
  }

  int hdrlen = TSHttpHdrLengthGet(response.buffer, response.header);
  TSHttpHdrPrint(response.buffer, response.header, trq->writeio.iobuf);
  TSVIONBytesSet(trq->writeio.vio, hdrlen);
  TSVIOReenable(trq->writeio.vio);
  TSStatIntIncrement(StatCountBytes, hdrlen);

  return TS_SUCCESS;
}

static int
DashboardInterceptHook(TSCont contp, TSEvent event, void *edata)
{
  argument_type arg(edata);

  switch (event) {
  case TS_EVENT_NET_ACCEPT: {
    DashboardRequest *trq = static_cast<DashboardRequest *>(TSContDataGet(contp));
    TSStatIntIncrement(StatCountResponses, 1);
    TSContDataSet(contp, trq);
    trq->readio.read(arg.vc, contp);
    return TS_EVENT_NONE;
  }

  case TS_EVENT_NET_ACCEPT_FAILED: {
    DashboardRequest *trq = static_cast<DashboardRequest *>(TSContDataGet(contp));
    delete trq;
    TSContDestroy(contp);
    return TS_EVENT_NONE;
  }

  case TS_EVENT_VCONN_READ_READY: {
    argument_type        cdata    = TSContDataGet(contp);
    DashboardRequest    *trq      = static_cast<DashboardRequest *>(cdata.ptr);
    DashboardHttpHeader &rqheader = trq->rqheader;

    TSIOBufferBlock blk;
    TSParseResult   result = TS_PARSE_CONT;

    for (blk = TSIOBufferReaderStart(trq->readio.reader); blk; blk = TSIOBufferBlockNext(blk)) {
      const char  *ptr;
      const char  *end;
      int64_t      nbytes;
      TSHttpStatus status = static_cast<TSHttpStatus>(trq->statusCode);

      ptr = TSIOBufferBlockReadStart(blk, trq->readio.reader, &nbytes);
      if (ptr == nullptr || nbytes == 0) {
        continue;
      }

      end    = ptr + nbytes;
      result = TSHttpHdrParseReq(rqheader.parser, rqheader.buffer, rqheader.header, &ptr, end);
      switch (result) {
      case TS_PARSE_ERROR:
        DashboardRequestDestroy(trq, arg.vio, contp);
        return TS_EVENT_ERROR;

      case TS_PARSE_DONE: {
        // Verify GET method
        int         method_len;
        const char *method = TSHttpHdrMethodGet(rqheader.buffer, rqheader.header, &method_len);
        if (method != TS_HTTP_METHOD_GET) {
          status = TS_HTTP_STATUS_METHOD_NOT_ALLOWED;
        }

        trq->writeio.write(TSVIOVConnGet(arg.vio), contp);
        TSVIONBytesSet(trq->writeio.vio, 0);

        if (WriteResponseHeader(trq, status) != TS_SUCCESS) {
          VERROR("failure writing response");
          return TS_EVENT_ERROR;
        }
        return TS_EVENT_NONE;
      }

      case TS_PARSE_CONT:
        break;
      }
    }

    TSReleaseAssert(result == TS_PARSE_CONT);
    TSVIOReenable(arg.vio);
    return TS_EVENT_NONE;
  }

  case TS_EVENT_VCONN_WRITE_READY: {
    argument_type     cdata = TSContDataGet(contp);
    DashboardRequest *trq   = static_cast<DashboardRequest *>(cdata.ptr);

    if (trq->nbytes) {
      int64_t nbytes  = trq->nbytes;
      nbytes          = TSIOBufferWrite(trq->writeio.iobuf, trq->body.c_str(), nbytes);
      trq->nbytes    -= nbytes;
      TSStatIntIncrement(StatCountBytes, nbytes);
      TSVIONBytesSet(arg.vio, TSVIONBytesGet(arg.vio) + nbytes);
      TSVIOReenable(arg.vio);
    }
    return TS_EVENT_NONE;
  }

  case TS_EVENT_ERROR:
  case TS_EVENT_VCONN_EOS: {
    argument_type     cdata = TSContDataGet(contp);
    DashboardRequest *trq   = static_cast<DashboardRequest *>(cdata.ptr);
    DashboardRequestDestroy(trq, arg.vio, contp);
    return event == TS_EVENT_ERROR ? TS_EVENT_ERROR : TS_EVENT_NONE;
  }

  case TS_EVENT_VCONN_READ_COMPLETE:
    return TS_EVENT_NONE;

  case TS_EVENT_VCONN_WRITE_COMPLETE: {
    argument_type     cdata = TSContDataGet(contp);
    DashboardRequest *trq   = static_cast<DashboardRequest *>(cdata.ptr);

    if (trq->nbytes) {
      trq->writeio.write(TSVIOVConnGet(arg.vio), contp);
      TSVIONBytesSet(trq->writeio.vio, trq->nbytes);
    } else {
      DashboardRequestDestroy(trq, arg.vio, contp);
    }
    return TS_EVENT_NONE;
  }

  case TS_EVENT_TIMEOUT:
    return TS_EVENT_NONE;

  default:
    VERROR("unexpected event %s (%d) edata=%p", TSHttpEventNameLookup(event), event, arg.ptr);
    return TS_EVENT_ERROR;
  }
}

static void
DashboardSetupIntercept(DashboardRequest *req, TSHttpTxn txn)
{
  TSCont cnt = TSContCreate(DashboardInterceptHook, TSMutexCreate());
  TSContDataSet(cnt, req);
  TSHttpTxnServerIntercept(cnt, txn);
}

// ---- Stats Collection ----

static int64_t
get_stat(const char *name)
{
  int id;
  if (TSStatFindName(name, &id) == TS_SUCCESS) {
    return TSStatIntGet(id);
  }
  return 0;
}

static std::string
build_stats_json()
{
  std::string json;
  json.reserve(8192);
  json += "{\n";

  // Meta
  char hostname[256];
  gethostname(hostname, sizeof(hostname));
  json += "\"meta\": {\n";
  json += "  \"version\": \"";
  json += TSTrafficServerVersionGet();
  json += "\",\n";
  json += "  \"hostname\": \"";
  json += hostname;
  json += "\",\n";

  char buf[128];
  snprintf(buf, sizeof(buf), "  \"uptime\": %" PRId64 "\n", (int64_t)(time(nullptr) - PluginStartTime));
  json += buf;
  json += "},\n";

  // Cache capacity
  json += "\"cache\": {\n";
  snprintf(buf, sizeof(buf), "  \"bytes_used\": %" PRId64 ",\n", get_stat("proxy.process.cache.bytes_used"));
  json += buf;
  snprintf(buf, sizeof(buf), "  \"bytes_total\": %" PRId64 ",\n", get_stat("proxy.process.cache.bytes_total"));
  json += buf;
  snprintf(buf, sizeof(buf), "  \"ram_cache_bytes_used\": %" PRId64 ",\n", get_stat("proxy.process.cache.ram_cache.bytes_used"));
  json += buf;
  snprintf(buf, sizeof(buf), "  \"ram_cache_total_bytes\": %" PRId64 ",\n", get_stat("proxy.process.cache.ram_cache.total_bytes"));
  json += buf;
  snprintf(buf, sizeof(buf), "  \"percent_full\": %" PRId64 ",\n", get_stat("proxy.process.cache.percent_full"));
  json += buf;
  snprintf(buf, sizeof(buf), "  \"stripes\": %" PRId64 ",\n", get_stat("proxy.process.cache.stripes"));
  json += buf;
  snprintf(buf, sizeof(buf), "  \"lock_contention\": %" PRId64 ",\n", get_stat("proxy.process.cache.stripe.lock_contention"));
  json += buf;
  snprintf(buf, sizeof(buf), "  \"writer_lock_contention\": %" PRId64 ",\n",
           get_stat("proxy.process.cache.writer.lock_contention"));
  json += buf;

  // Cache operations
  snprintf(buf, sizeof(buf), "  \"lookup_success\": %" PRId64 ",\n", get_stat("proxy.process.cache.lookup.success"));
  json += buf;
  snprintf(buf, sizeof(buf), "  \"lookup_failure\": %" PRId64 ",\n", get_stat("proxy.process.cache.lookup.failure"));
  json += buf;
  snprintf(buf, sizeof(buf), "  \"read_success\": %" PRId64 ",\n", get_stat("proxy.process.cache.read.success"));
  json += buf;
  snprintf(buf, sizeof(buf), "  \"read_failure\": %" PRId64 ",\n", get_stat("proxy.process.cache.read.failure"));
  json += buf;
  snprintf(buf, sizeof(buf), "  \"write_success\": %" PRId64 ",\n", get_stat("proxy.process.cache.write.success"));
  json += buf;
  snprintf(buf, sizeof(buf), "  \"write_failure\": %" PRId64 ",\n", get_stat("proxy.process.cache.write.failure"));
  json += buf;
  snprintf(buf, sizeof(buf), "  \"read_active\": %" PRId64 ",\n", get_stat("proxy.process.cache.read.active"));
  json += buf;
  snprintf(buf, sizeof(buf), "  \"write_active\": %" PRId64 ",\n", get_stat("proxy.process.cache.write.active"));
  json += buf;

  // Cache quality
  snprintf(buf, sizeof(buf), "  \"ram_cache_hits\": %" PRId64 ",\n", get_stat("proxy.process.cache.ram_cache.hits"));
  json += buf;
  snprintf(buf, sizeof(buf), "  \"ram_cache_misses\": %" PRId64 ",\n", get_stat("proxy.process.cache.ram_cache.misses"));
  json += buf;
  snprintf(buf, sizeof(buf), "  \"directory_wrap\": %" PRId64 ",\n", get_stat("proxy.process.cache.directory_wrap"));
  json += buf;
  snprintf(buf, sizeof(buf), "  \"direntries_used\": %" PRId64 ",\n", get_stat("proxy.process.cache.direntries.used"));
  json += buf;
  snprintf(buf, sizeof(buf), "  \"direntries_total\": %" PRId64 "\n", get_stat("proxy.process.cache.direntries.total"));
  json += buf;
  json += "},\n";

  // Helper lambda
  auto js = [&](const char *key, int64_t val, bool last = false) {
    snprintf(buf, sizeof(buf), "  \"%s\": %" PRId64 "%s\n", key, val, last ? "" : ",");
    json += buf;
  };
  auto jsd = [&](const char *key, int val, bool last = false) {
    snprintf(buf, sizeof(buf), "  \"%s\": %d%s\n", key, val, last ? "" : ",");
    json += buf;
  };

  // HTTP
  json += "\"http\": {\n";
  js("cache_hit_fresh", get_stat("proxy.process.http.cache_hit_fresh"));
  js("cache_hit_mem_fresh", get_stat("proxy.process.http.cache_hit_mem_fresh"));
  js("cache_hit_revalidated", get_stat("proxy.process.http.cache_hit_revalidated"));
  js("cache_hit_stale_served", get_stat("proxy.process.http.cache_hit_stale_served"));
  js("cache_miss_cold", get_stat("proxy.process.http.cache_miss_cold"));
  js("cache_miss_changed", get_stat("proxy.process.http.cache_miss_changed"));
  js("cache_miss_not_cacheable", get_stat("proxy.process.http.cache_miss_client_not_cacheable"));
  js("cache_lookups", get_stat("proxy.process.http.cache_lookups"));
  js("completed_requests", get_stat("proxy.process.http.completed_requests"));
  js("incoming_requests", get_stat("proxy.process.http.incoming_requests"));
  js("outgoing_requests", get_stat("proxy.process.http.outgoing_requests"));
  js("total_transactions_time", get_stat("proxy.process.http.total_transactions_time"));
  js("get_requests", get_stat("proxy.process.http.get_requests"));
  js("post_requests", get_stat("proxy.process.http.post_requests"));
  js("put_requests", get_stat("proxy.process.http.put_requests"));
  js("delete_requests", get_stat("proxy.process.http.delete_requests"));
  js("head_requests", get_stat("proxy.process.http.head_requests"));
  js("connect_requests", get_stat("proxy.process.http.connect_requests"));
  js("options_requests", get_stat("proxy.process.http.options_requests"));
  js("purge_requests", get_stat("proxy.process.http.purge_requests"));
  js("invalid_client_requests", get_stat("proxy.process.http.invalid_client_requests"));
  js("missing_host_hdr", get_stat("proxy.process.http.missing_host_hdr"));
  js("tunnels", get_stat("proxy.process.http.tunnels"));
  js("ua_request_header_size", get_stat("proxy.process.http.user_agent_request_header_total_size"));
  js("ua_response_header_size", get_stat("proxy.process.http.user_agent_response_header_total_size"));
  js("os_request_header_size", get_stat("proxy.process.http.origin_server_request_header_total_size"));
  js("os_response_header_size", get_stat("proxy.process.http.origin_server_response_header_total_size"), true);
  json += "},\n";

  // TCP transaction types
  json += "\"tcp\": {\n";
  js("hit", get_stat("proxy.process.http.tcp_hit_count"));
  js("miss", get_stat("proxy.process.http.tcp_miss_count"));
  js("refresh_hit", get_stat("proxy.process.http.tcp_refresh_hit_count"));
  js("refresh_miss", get_stat("proxy.process.http.tcp_refresh_miss_count"));
  js("ims_hit", get_stat("proxy.process.http.tcp_ims_hit_count"));
  js("ims_miss", get_stat("proxy.process.http.tcp_ims_miss_count"));
  js("expired_miss", get_stat("proxy.process.http.tcp_expired_miss_count"));
  js("client_refresh", get_stat("proxy.process.http.tcp_client_refresh_count"), true);
  json += "},\n";

  // Connections
  json += "\"connections\": {\n";
  jsd("client_total", TSHttpCurrentClientConnectionsGet());
  jsd("client_active", TSHttpCurrentActiveClientConnectionsGet());
  jsd("client_idle", TSHttpCurrentIdleClientConnectionsGet());
  jsd("server", TSHttpCurrentServerConnectionsGet());
  jsd("cache", TSHttpCurrentCacheConnectionsGet());
  js("total_client_conns", get_stat("proxy.process.http.total_client_connections"));
  js("total_server_conns", get_stat("proxy.process.http.total_server_connections"));
  js("total_incoming", get_stat("proxy.process.http.total_incoming_connections"));
  js("pooled_server", get_stat("proxy.process.http.pooled_server_connections"));
  js("broken_server", get_stat("proxy.process.http.broken_server_connections"));
  js("throttled_in", get_stat("proxy.process.net.connections_throttled_in"));
  js("throttled_out", get_stat("proxy.process.net.connections_throttled_out"));
  js("tcp_accepts", get_stat("proxy.process.tcp.total_accepts"), true);
  json += "},\n";

  // Origin
  json += "\"origin\": {\n";
  js("make_new", get_stat("proxy.process.http.origin.make_new"));
  js("reuse", get_stat("proxy.process.http.origin.reuse"));
  js("reuse_fail", get_stat("proxy.process.http.origin.reuse_fail"));
  js("close_private", get_stat("proxy.process.http.origin.close_private"));
  js("not_found", get_stat("proxy.process.http.origin.not_found"));
  js("shutdown_tunnel_server_plugin", get_stat("proxy.process.http.origin_shutdown.tunnel_server_plugin_tunnel"));
  js("shutdown_tunnel_server_eos", get_stat("proxy.process.http.origin_shutdown.tunnel_server_eos"));
  js("shutdown_tunnel_abort", get_stat("proxy.process.http.origin_shutdown.tunnel_abort"), true);
  json += "},\n";

  // Bandwidth
  json += "\"bandwidth\": {\n";
  js("ua_response_bytes", get_stat("proxy.process.http.user_agent_response_document_total_size"));
  js("os_response_bytes", get_stat("proxy.process.http.origin_server_response_document_total_size"));
  js("ua_request_bytes", get_stat("proxy.process.http.user_agent_request_document_total_size"));
  js("os_request_bytes", get_stat("proxy.process.http.origin_server_request_document_total_size"));
  js("net_read_bytes", get_stat("proxy.process.net.read_bytes"));
  js("net_write_bytes", get_stat("proxy.process.net.write_bytes"), true);
  json += "},\n";

  // DNS
  json += "\"dns\": {\n";
  js("total_lookups", get_stat("proxy.process.dns.total_dns_lookups"));
  js("lookup_successes", get_stat("proxy.process.dns.lookup_successes"));
  js("lookup_failures", get_stat("proxy.process.dns.lookup_failures"));
  js("in_flight", get_stat("proxy.process.dns.in_flight"));
  js("retries", get_stat("proxy.process.dns.retries"));
  js("max_retries_exceeded", get_stat("proxy.process.dns.max_retries_exceeded"), true);
  json += "},\n";

  // HostDB
  json += "\"hostdb\": {\n";
  js("total_lookups", get_stat("proxy.process.hostdb.total_lookups"));
  js("total_hits", get_stat("proxy.process.hostdb.total_hits"));
  js("total_serve_stale", get_stat("proxy.process.hostdb.total_serve_stale"));
  js("ttl_expires", get_stat("proxy.process.hostdb.ttl_expires"), true);
  json += "},\n";

  // Response Codes
  json += "\"response_codes\": {\n";
  js("1xx", get_stat("proxy.process.http.1xx_responses"));
  js("2xx", get_stat("proxy.process.http.2xx_responses"));
  js("3xx", get_stat("proxy.process.http.3xx_responses"));
  js("4xx", get_stat("proxy.process.http.4xx_responses"));
  js("5xx", get_stat("proxy.process.http.5xx_responses"), true);
  json += "},\n";

  // Memory
  json += "\"memory\": {\n";
  js("rss", get_stat("proxy.process.traffic_server.memory.rss"), true);
  json += "},\n";

  // Event Loop
  json += "\"eventloop\": {\n";
  js("count_10s", get_stat("proxy.process.eventloop.count.10s"));
  js("events_10s", get_stat("proxy.process.eventloop.events.10s"));
  js("time_min_10s", get_stat("proxy.process.eventloop.time.min.10s"));
  js("time_max_10s", get_stat("proxy.process.eventloop.time.max.10s"));
  js("drain_queue_max_10s", get_stat("proxy.process.eventloop.drain.queue.max.10s"));
  js("io_wait_max_10s", get_stat("proxy.process.eventloop.io.wait.max.10s"), true);
  json += "},\n";

  // Network I/O
  json += "\"net\": {\n";
  js("handler_run", get_stat("proxy.process.net.net_handler_run"));
  js("read_bytes", get_stat("proxy.process.net.read_bytes"));
  js("write_bytes", get_stat("proxy.process.net.write_bytes"));
  js("calls_to_read", get_stat("proxy.process.net.calls_to_read"));
  js("calls_to_write", get_stat("proxy.process.net.calls_to_write"));
  js("calls_to_read_nodata", get_stat("proxy.process.net.calls_to_read_nodata"));
  js("accepts_open", get_stat("proxy.process.net.accepts_currently_open"));
  js("connections_open", get_stat("proxy.process.net.connections_currently_open"), true);
  json += "},\n";

  // Logging
  json += "\"logging\": {\n";
  js("bytes_written", get_stat("proxy.process.log.bytes_written_to_disk"));
  js("bytes_flushed", get_stat("proxy.process.log.bytes_flush_to_disk"));
  js("num_flushes", get_stat("proxy.process.log.num_flush_to_disk"));
  js("space_used", get_stat("proxy.process.log.log_files_space_used"));
  js("files_open", get_stat("proxy.process.log.log_files_open"));
  js("access_ok", get_stat("proxy.process.log.event_log_access_ok"));
  js("access_fail", get_stat("proxy.process.log.event_log_access_fail"));
  js("bytes_lost", get_stat("proxy.process.log.bytes_lost_before_written_to_disk"), true);
  json += "},\n";

  // SSL/TLS
  json += "\"ssl\": {\n";
  js("total_handshake_in", get_stat("proxy.process.ssl.total_attempts_handshake_count_in"));
  js("total_handshake_out", get_stat("proxy.process.ssl.total_attempts_handshake_count_out"));
  js("success_handshake_in", get_stat("proxy.process.ssl.total_success_handshake_count_in"));
  js("success_handshake_out", get_stat("proxy.process.ssl.total_success_handshake_count_out"));
  js("session_cache_hit", get_stat("proxy.process.ssl.ssl_session_cache_hit"));
  js("session_cache_miss", get_stat("proxy.process.ssl.ssl_session_cache_miss"));
  js("session_cache_eviction", get_stat("proxy.process.ssl.ssl_session_cache_eviction"));
  js("session_cache_timeout", get_stat("proxy.process.ssl.ssl_session_cache_timeout"));
  js("origin_session_reused", get_stat("proxy.process.ssl.origin_session_reused"));
  js("origin_session_cache_hit", get_stat("proxy.process.ssl.ssl_origin_session_cache_hit"));
  js("origin_session_cache_miss", get_stat("proxy.process.ssl.ssl_origin_session_cache_miss"));
  js("tlsv12", get_stat("proxy.process.ssl.ssl_total_tlsv12"));
  js("tlsv13", get_stat("proxy.process.ssl.ssl_total_tlsv13"));
  js("error_ssl", get_stat("proxy.process.ssl.ssl_error_ssl"));
  js("error_syscall", get_stat("proxy.process.ssl.ssl_error_syscall"));
  js("ua_bad_cert", get_stat("proxy.process.ssl.user_agent_bad_cert"));
  js("ua_expired_cert", get_stat("proxy.process.ssl.user_agent_expired_cert"));
  js("ua_revoked_cert", get_stat("proxy.process.ssl.user_agent_revoked_cert"));
  js("ua_unknown_ca", get_stat("proxy.process.ssl.user_agent_unknown_ca"));
  js("ua_cert_verify_failed", get_stat("proxy.process.ssl.user_agent_cert_verify_failed"));
  js("ua_decryption_failed", get_stat("proxy.process.ssl.user_agent_decryption_failed"));
  js("os_bad_cert", get_stat("proxy.process.ssl.origin_server_bad_cert"));
  js("os_expired_cert", get_stat("proxy.process.ssl.origin_server_expired_cert"));
  js("os_unknown_ca", get_stat("proxy.process.ssl.origin_server_unknown_ca"));
  js("os_cert_verify_failed", get_stat("proxy.process.ssl.origin_server_cert_verify_failed"), true);
  json += "},\n";

  // HTTP/2
  json += "\"http2\": {\n";
  js("current_client_conns", get_stat("proxy.process.http2.current_client_connections"));
  js("current_server_conns", get_stat("proxy.process.http2.current_server_connections"));
  js("current_client_streams", get_stat("proxy.process.http2.current_client_streams"));
  js("total_client_conns", get_stat("proxy.process.http2.total_client_connections"));
  js("total_server_conns", get_stat("proxy.process.http2.total_server_connections"));
  js("total_client_streams", get_stat("proxy.process.http2.total_client_streams"));
  js("connection_errors", get_stat("proxy.process.http2.connection_errors"));
  js("stream_errors", get_stat("proxy.process.http2.stream_errors"));
  js("max_concurrent_exceeded_in", get_stat("proxy.process.http2.max_concurrent_streams_exceeded_in"));
  js("session_die_error", get_stat("proxy.process.http2.session_die_error"));
  js("session_die_active", get_stat("proxy.process.http2.session_die_active"));
  js("session_die_inactive", get_stat("proxy.process.http2.session_die_inactive"));
  js("session_die_eos", get_stat("proxy.process.http2.session_die_eos"));
  js("data_frames_in", get_stat("proxy.process.http2.data_frames_in"));
  js("headers_frames_in", get_stat("proxy.process.http2.headers_frames_in"));
  js("rst_stream_frames_in", get_stat("proxy.process.http2.rst_stream_frames_in"), true);
  json += "},\n";

  // Tunnel
  json += "\"tunnel\": {\n";
  js("current_active", get_stat("proxy.process.tunnel.current_active_connections"));
  js("blind_tcp_client", get_stat("proxy.process.tunnel.total_client_connections_blind_tcp"));
  js("tls_tunnel_client", get_stat("proxy.process.tunnel.total_client_connections_tls_tunnel"));
  js("tls_forward_client", get_stat("proxy.process.tunnel.total_client_connections_tls_forward"));
  js("tls_http_client", get_stat("proxy.process.tunnel.total_client_connections_tls_http"), true);
  json += "},\n";

  // Milestones (cumulative avg nanoseconds per phase)
  json += "\"milestones\": {\n";
  js("ua_begin", get_stat("proxy.process.http.milestone.ua_begin"));
  js("ua_first_read", get_stat("proxy.process.http.milestone.ua_first_read"));
  js("ua_read_header_done", get_stat("proxy.process.http.milestone.ua_read_header_done"));
  js("cache_open_read_begin", get_stat("proxy.process.http.milestone.cache_open_read_begin"));
  js("cache_open_read_end", get_stat("proxy.process.http.milestone.cache_open_read_end"));
  js("cache_open_write_begin", get_stat("proxy.process.http.milestone.cache_open_write_begin"));
  js("cache_open_write_end", get_stat("proxy.process.http.milestone.cache_open_write_end"));
  js("dns_lookup_begin", get_stat("proxy.process.http.milestone.dns_lookup_begin"));
  js("dns_lookup_end", get_stat("proxy.process.http.milestone.dns_lookup_end"));
  js("server_first_connect", get_stat("proxy.process.http.milestone.server_first_connect"));
  js("server_connect", get_stat("proxy.process.http.milestone.server_connect"));
  js("server_connect_end", get_stat("proxy.process.http.milestone.server_connect_end"));
  js("server_begin_write", get_stat("proxy.process.http.milestone.server_begin_write"));
  js("server_first_read", get_stat("proxy.process.http.milestone.server_first_read"));
  js("server_read_header_done", get_stat("proxy.process.http.milestone.server_read_header_done"));
  js("server_close", get_stat("proxy.process.http.milestone.server_close"));
  js("ua_begin_write", get_stat("proxy.process.http.milestone.ua_begin_write"));
  js("ua_close", get_stat("proxy.process.http.milestone.ua_close"));
  js("sm_start", get_stat("proxy.process.http.milestone.sm_start"));
  js("sm_finish", get_stat("proxy.process.http.milestone.sm_finish"), true);
  json += "},\n";

  // Errors
  json += "\"errors\": {\n";
  js("client_abort", get_stat("proxy.process.http.err_client_abort_count_stat"));
  js("connect_fail", get_stat("proxy.process.http.err_connect_fail_count_stat"));
  js("client_read_error", get_stat("proxy.process.http.err_client_read_error_count"));
  js("cache_read_error", get_stat("proxy.process.http.cache_read_errors"));
  js("cache_write_error", get_stat("proxy.process.http.cache_write_errors"));
  js("proxy_loop_detected", get_stat("proxy.process.http.http_proxy_loop_detected"));
  js("no_remap_matched", get_stat("proxy.process.http.no_remap_matched"), true);
  json += "}\n";

  json += "}\n";
  return json;
}

// ---- HTML Dashboard (loaded from file) ----

static std::string DashboardHtmlPath;

static std::string
build_dashboard_html()
{
  if (DashboardHtmlPath.empty()) {
    return "<html><body>Dashboard HTML path not configured. "
           "Pass path as plugin argument: @plugin=dashboard.so /path/to/dashboard.html</body></html>";
  }
  std::ifstream f(DashboardHtmlPath);
  if (!f.is_open()) {
    return "<html><body>Failed to open dashboard file: " + DashboardHtmlPath + "</body></html>";
  }
  std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  return content;
}

// Legacy embedded HTML removed - dashboard is now served from external file
#if 0
static std::string
build_dashboard_html_embedded()
{
  return std::string(R"HTMLRAW(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ATS Dashboard</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #0f172a; color: #e2e8f0; min-height: 100vh;
  }
  .header {
    background: #1e293b; border-bottom: 1px solid #334155;
    padding: 12px 24px; display: flex; align-items: center;
    justify-content: space-between; flex-wrap: wrap; gap: 12px;
  }
  .header h1 { font-size: 20px; color: #38bdf8; font-weight: 600; }
  .header-info { display: flex; gap: 20px; align-items: center; font-size: 13px; color: #94a3b8; }
  .header-info span { display: flex; align-items: center; gap: 6px; }
  .live-dot {
    width: 8px; height: 8px; border-radius: 50%;
    background: #22c55e; animation: pulse 2s infinite;
  }
  @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }
  .container { max-width: 1400px; margin: 0 auto; padding: 16px; }

  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-bottom: 16px; }
  .card {
    background: #1e293b; border-radius: 10px; padding: 14px 16px;
    border: 1px solid #334155;
  }
  .card-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: #64748b; margin-bottom: 6px; }
  .card-value { font-size: 28px; font-weight: 700; font-family: 'SF Mono', 'Fira Code', monospace; }
  .card-sub { font-size: 12px; color: #64748b; margin-top: 2px; font-family: 'SF Mono', monospace; }
  .card-value.green { color: #22c55e; }
  .card-value.blue { color: #38bdf8; }
  .card-value.amber { color: #f59e0b; }

  .panel {
    background: #1e293b; border-radius: 10px; padding: 14px 16px;
    border: 1px solid #334155;
  }
  .panel-title { font-size: 13px; font-weight: 600; color: #cbd5e1; margin-bottom: 10px; display: flex; justify-content: space-between; align-items: center; }
  .panel-title .panel-val { font-family: 'SF Mono', monospace; font-size: 14px; color: #94a3b8; }

  .graph-row { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 16px; }

  .legend { display: flex; gap: 12px; margin-bottom: 6px; font-size: 11px; color: #94a3b8; }
  .legend-dot {
    display: inline-block; width: 8px; height: 8px;
    border-radius: 50%; margin-right: 3px; vertical-align: middle;
  }

  .detail-row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 16px; }

  .conn-bar-wrap { margin-bottom: 8px; }
  .conn-bar-label {
    display: flex; justify-content: space-between; font-size: 12px;
    color: #94a3b8; margin-bottom: 3px;
  }
  .conn-bar {
    height: 20px; background: #334155; border-radius: 5px; overflow: hidden;
  }
  .conn-bar-fill {
    height: 100%; border-radius: 5px; transition: width 0.5s ease;
    display: flex; align-items: center; padding-left: 6px;
    font-size: 11px; font-weight: 600; color: #fff; min-width: 24px;
  }

  .info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 6px 16px; }
  .info-item { display: flex; justify-content: space-between; align-items: baseline; padding: 3px 0; border-bottom: 1px solid #1e293b; }
  .info-label { font-size: 12px; color: #64748b; }
  .info-val { font-size: 13px; font-weight: 600; font-family: 'SF Mono', monospace; color: #e2e8f0; }
  .info-val.green { color: #22c55e; }

  .progress-inline { margin-bottom: 8px; }
  .progress-header {
    display: flex; justify-content: space-between; align-items: center;
    font-size: 12px; color: #94a3b8; margin-bottom: 4px;
  }
  .progress-header .pct { font-family: 'SF Mono', monospace; font-weight: 600; }
  .progress-bar {
    height: 6px; background: #334155; border-radius: 3px; overflow: hidden;
  }
  .progress-fill {
    height: 100%; border-radius: 3px; transition: width 0.5s ease;
  }
  .progress-detail { font-size: 11px; color: #475569; margin-top: 2px; }

  .error-banner {
    background: #7f1d1d; color: #fca5a5; padding: 8px 16px;
    border-radius: 8px; font-size: 13px; margin-bottom: 12px;
    display: none; text-align: center;
  }
</style>
</head>
<body>

<div class="header">
  <h1>ATS Dashboard</h1>
  <div class="header-info">
    <span id="h-version">--</span>
    <span id="h-hostname">--</span>
    <span id="h-uptime">--</span>
    <span><div class="live-dot"></div> Live</span>
  </div>
</div>

<div class="container">
  <div id="error-banner" class="error-banner"></div>

  <div class="cards">
    <div class="card">
      <div class="card-label">Total Requests</div>
      <div class="card-value blue" id="m-requests">--</div>
      <div class="card-sub" id="m-rps">-- req/s</div>
    </div>
    <div class="card">
      <div class="card-label">Cache Hit Ratio</div>
      <div class="card-value green" id="m-hitratio">--%</div>
      <div class="card-sub" id="m-hitdetail">-- hits / -- misses</div>
    </div>
    <div class="card">
      <div class="card-label">Active Connections</div>
      <div class="card-value amber" id="m-conns">--</div>
      <div class="card-sub" id="m-conndetail">-- total / -- idle</div>
    </div>
    <div class="card">
      <div class="card-label">Avg Latency</div>
      <div class="card-value blue" id="m-latency">--</div>
      <div class="card-sub" id="m-latdetail">per transaction</div>
    </div>
    <div class="card">
      <div class="card-label">Bandwidth</div>
      <div class="card-value blue" id="m-bandwidth">--</div>
      <div class="card-sub" id="m-bwdetail">-- to origin</div>
    </div>
  </div>

  <div class="graph-row">
    <div class="panel">
      <div class="panel-title">Throughput (2 min) <span class="panel-val" id="sp-rps-val">-- req/s</span></div>
      <svg id="spark-rps" width="100%" height="100" viewBox="0 0 360 100" preserveAspectRatio="none"></svg>
    </div>
    <div class="panel">
      <div class="panel-title">Bandwidth (2 min) <span class="panel-val" id="sp-bw-val">--/s</span></div>
      <div class="legend">
        <span><span class="legend-dot" style="background:#38bdf8"></span>Client</span>
        <span><span class="legend-dot" style="background:#a78bfa"></span>Origin</span>
      </div>
      <svg id="spark-bw" width="100%" height="90" viewBox="0 0 360 90" preserveAspectRatio="none"></svg>
    </div>
    <div class="panel">
      <div class="panel-title">Cache Hit Rate (2 min) <span class="panel-val" id="sp-hit-val">--%</span></div>
      <div class="legend">
        <span><span class="legend-dot" style="background:#22c55e"></span>Hits</span>
        <span><span class="legend-dot" style="background:#ef4444"></span>Misses</span>
      </div>
      <svg id="spark-hit" width="100%" height="90" viewBox="0 0 360 90" preserveAspectRatio="none"></svg>
    </div>
  </div>

  <div class="detail-row">
    <div class="panel">
      <div class="panel-title">Connections</div>
      <div class="conn-bar-wrap">
        <div class="conn-bar-label"><span>Client Total</span><span id="conn-client-total">0</span></div>
        <div class="conn-bar"><div class="conn-bar-fill" id="conn-client-bar" style="width:0%;background:#38bdf8">0</div></div>
      </div>
      <div class="conn-bar-wrap">
        <div class="conn-bar-label"><span>Client Active</span><span id="conn-client-active">0</span></div>
        <div class="conn-bar"><div class="conn-bar-fill" id="conn-active-bar" style="width:0%;background:#f59e0b">0</div></div>
      </div>
      <div class="conn-bar-wrap">
        <div class="conn-bar-label"><span>Client Idle</span><span id="conn-client-idle">0</span></div>
        <div class="conn-bar"><div class="conn-bar-fill" id="conn-idle-bar" style="width:0%;background:#64748b">0</div></div>
      </div>
      <div class="conn-bar-wrap">
        <div class="conn-bar-label"><span>Server</span><span id="conn-server">0</span></div>
        <div class="conn-bar"><div class="conn-bar-fill" id="conn-server-bar" style="width:0%;background:#a78bfa">0</div></div>
      </div>
      <div class="conn-bar-wrap">
        <div class="conn-bar-label"><span>Cache</span><span id="conn-cache">0</span></div>
        <div class="conn-bar"><div class="conn-bar-fill" id="conn-cache-bar" style="width:0%;background:#22c55e">0</div></div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-title">Details</div>
      <div class="progress-inline">
        <div class="progress-header">
          <span>Disk Cache</span>
          <span class="pct" id="cache-disk-pct">--%</span>
        </div>
        <div class="progress-bar">
          <div class="progress-fill" id="cache-disk-bar" style="width:0%;background:#22c55e"></div>
        </div>
        <div class="progress-detail" id="cache-disk-detail">-- / --</div>
      </div>
      <div class="progress-inline">
        <div class="progress-header">
          <span>RAM Cache</span>
          <span class="pct" id="cache-ram-pct">--%</span>
        </div>
        <div class="progress-bar">
          <div class="progress-fill" id="cache-ram-bar" style="width:0%;background:#22c55e"></div>
        </div>
        <div class="progress-detail" id="cache-ram-detail">-- / --</div>
      </div>
      <div class="info-grid" style="margin-top:10px">
        <div class="info-item"><span class="info-label">Client BW</span><span class="info-val" id="bw-client-total">--</span></div>
        <div class="info-item"><span class="info-label">Origin BW</span><span class="info-val" id="bw-origin-total">--</span></div>
        <div class="info-item"><span class="info-label">DNS</span><span class="info-val" id="dns-total">--</span></div>
        <div class="info-item"><span class="info-label">DNS OK</span><span class="info-val green" id="dns-success-rate">--%</span></div>
        <div class="info-item"><span class="info-label">HostDB</span><span class="info-val" id="hostdb-total">--</span></div>
        <div class="info-item"><span class="info-label">HostDB Hit</span><span class="info-val green" id="hostdb-hit-rate">--%</span></div>
        <div class="info-item"><span class="info-label">Stripes</span><span class="info-val" id="ci-stripes">--</span></div>
        <div class="info-item"><span class="info-label">Dir Wraps</span><span class="info-val" id="ci-dirwrap">--</span></div>
        <div class="info-item"><span class="info-label">Dir Used</span><span class="info-val" id="ci-dirent-used">--</span></div>
        <div class="info-item"><span class="info-label">Dir Total</span><span class="info-val" id="ci-dirent-total">--</span></div>
        <div class="info-item"><span class="info-label">Active Rd</span><span class="info-val" id="ci-read-active">--</span></div>
        <div class="info-item"><span class="info-label">Active Wr</span><span class="info-val" id="ci-write-active">--</span></div>
        <div class="info-item"><span class="info-label">Aborts</span><span class="info-val" id="err-abort">--</span></div>
        <div class="info-item"><span class="info-label">Conn Fail</span><span class="info-val" id="err-connect">--</span></div>
      </div>
    </div>
  </div>
</div>

<script>
(function() {
  const POLL = 2000, HSIZE = 60;
  let prev = null, prevTime = null;
  let rpsHistory = [], bwClientHistory = [], bwOriginHistory = [];
  let hitHistory = [], missHistory = [];

  function fmtB(b) {
    if (b === 0) return '0 B';
    const u = ['B','KB','MB','GB','TB'];
    const i = Math.floor(Math.log(b) / Math.log(1024));
    return (b / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0) + ' ' + u[i];
  }
  function fmtN(n) {
    if (n >= 1e9) return (n/1e9).toFixed(2)+'B';
    if (n >= 1e6) return (n/1e6).toFixed(2)+'M';
    if (n >= 1e3) return (n/1e3).toFixed(1)+'K';
    return n.toString();
  }
  function fmtUp(s) {
    const d=Math.floor(s/86400), h=Math.floor(s%86400/3600), m=Math.floor(s%3600/60);
    return d>0 ? d+'d '+h+'h '+m+'m' : h>0 ? h+'h '+m+'m' : m+'m';
  }
  function pctCol(p) { return p<70?'#22c55e':p<90?'#f59e0b':'#ef4444'; }
  function txt(id,v) { const e=document.getElementById(id); if(e) e.textContent=v; }

  function setBar(bid,vid,val,max) {
    const p = max>0 ? Math.min(100,val/max*100) : 0;
    const b=document.getElementById(bid), v=document.getElementById(vid);
    if(b){b.style.width=Math.max(p,2)+'%';b.textContent=val;}
    if(v) v.textContent=val;
  }

  function drawSpark(svgId, datasets, maxVal, h) {
    const svg = document.getElementById(svgId);
    if (!svg) return;
    const w = 360, pad = 2;
    if (datasets[0].data.length < 2) { svg.innerHTML = ''; return; }

    let grid = '';
    for (let i=0;i<=4;i++) {
      const y = pad + (i/4)*(h-2*pad);
      grid += '<line x1="0" y1="'+y+'" x2="'+w+'" y2="'+y+'" stroke="#334155" stroke-width="0.5"/>';
    }

    let lines = '';
    const autoMax = maxVal === 0;
    if (autoMax) {
      maxVal = 1;
      for (const ds of datasets) for (const v of ds.data) if (v > maxVal) maxVal = v;
      maxVal *= 1.1;
    }

    for (const ds of datasets) {
      const n = ds.data.length;
      const step = w / (HSIZE - 1);
      const off = HSIZE - n;
      let pts = '';
      for (let i=0;i<n;i++) {
        const x = (off+i)*step;
        const y = h - pad - (Math.min(ds.data[i],maxVal)/maxVal*(h-2*pad));
        pts += x.toFixed(1)+','+y.toFixed(1)+' ';
      }
      const sx = (off*step).toFixed(1), ex = ((off+n-1)*step).toFixed(1);
      const area = sx+','+(h-pad)+' '+pts+ex+','+(h-pad);
      lines += '<polygon points="'+area+'" fill="'+ds.color+'" opacity="0.12"/>';
      lines += '<polyline points="'+pts.trim()+'" fill="none" stroke="'+ds.color+'" stroke-width="1.5" opacity="0.9"/>';
    }
    svg.innerHTML = grid + lines;
  }

  function update(data) {
    const now = Date.now();
    const dt = prev ? (now - prevTime) / 1000 : 0;

    txt('h-version', 'ATS '+data.meta.version);
    txt('h-hostname', data.meta.hostname);
    txt('h-uptime', 'Up '+fmtUp(data.meta.uptime));

    const totalReqs = data.http.completed_requests;
    txt('m-requests', fmtN(totalReqs));

    const hits = data.http.cache_hit_fresh;
    const lookups = data.http.cache_lookups;
    const misses = data.http.cache_miss_cold;
    const ratio = lookups>0 ? (hits/lookups*100) : 0;
    txt('m-hitratio', ratio.toFixed(1)+'%');
    txt('m-hitdetail', fmtN(hits)+' hits / '+fmtN(misses)+' misses');

    txt('m-conns', data.connections.client_active);
    txt('m-conndetail', data.connections.client_total+' total / '+data.connections.client_idle+' idle');

    const uaB = data.bandwidth.ua_response_bytes;
    const osB = data.bandwidth.os_response_bytes;

    if (prev && dt > 0) {
      const rps = (totalReqs - prev.http.completed_requests) / dt;
      txt('m-rps', rps.toFixed(1)+' req/s');
      rpsHistory.push(rps);

      const bwC = (uaB - prev.bandwidth.ua_response_bytes) / dt;
      const bwO = (osB - prev.bandwidth.os_response_bytes) / dt;
      txt('m-bandwidth', fmtB(bwC)+'/s');
      txt('m-bwdetail', fmtB(bwO)+'/s to origin');
      bwClientHistory.push(bwC);
      bwOriginHistory.push(bwO);

      // Latency: delta total_transactions_time (nanoseconds) / delta completed_requests
      const dReqs = totalReqs - prev.http.completed_requests;
      const dTime = data.http.total_transactions_time - prev.http.total_transactions_time;
      if (dReqs > 0) {
        const avgNs = dTime / dReqs;
        if (avgNs >= 1e6) txt('m-latency', (avgNs/1e6).toFixed(1)+' ms');
        else if (avgNs >= 1e3) txt('m-latency', (avgNs/1e3).toFixed(0)+' us');
        else txt('m-latency', avgNs.toFixed(0)+' ns');
      }

      const dH = hits - prev.http.cache_hit_fresh;
      const dM = misses - prev.http.cache_miss_cold;
      const dT = dH + dM;
      const hPct = dT>0 ? dH/dT*100 : (lookups>0?ratio:0);
      const mPct = dT>0 ? dM/dT*100 : 0;
      hitHistory.push(hPct);
      missHistory.push(mPct);

      if (rpsHistory.length > HSIZE) rpsHistory.shift();
      if (bwClientHistory.length > HSIZE) { bwClientHistory.shift(); bwOriginHistory.shift(); }
      if (hitHistory.length > HSIZE) { hitHistory.shift(); missHistory.shift(); }

      txt('sp-rps-val', fmtN(Math.round(rps))+' req/s');
      txt('sp-bw-val', fmtB(bwC)+'/s');
      txt('sp-hit-val', hPct.toFixed(1)+'%');
    } else {
      txt('m-bandwidth', fmtB(uaB));
      txt('m-bwdetail', fmtB(osB)+' to origin');
    }

    // Sparklines
    drawSpark('spark-rps', [{data:rpsHistory, color:'#38bdf8'}], 0, 100);
    drawSpark('spark-bw', [{data:bwClientHistory, color:'#38bdf8'},{data:bwOriginHistory, color:'#a78bfa'}], 0, 90);
    drawSpark('spark-hit', [{data:hitHistory, color:'#22c55e'},{data:missHistory, color:'#ef4444'}], 100, 90);

    // Connections
    const mx = Math.max(data.connections.client_total, data.connections.server, 1);
    setBar('conn-client-bar','conn-client-total',data.connections.client_total,mx);
    setBar('conn-active-bar','conn-client-active',data.connections.client_active,mx);
    setBar('conn-idle-bar','conn-client-idle',data.connections.client_idle,mx);
    setBar('conn-server-bar','conn-server',data.connections.server,mx);
    setBar('conn-cache-bar','conn-cache',data.connections.cache,mx);

    // Cache health
    const dPct = data.cache.bytes_total>0 ? data.cache.bytes_used/data.cache.bytes_total*100 : data.cache.percent_full;
    txt('cache-disk-pct', dPct.toFixed(1)+'%');
    const db = document.getElementById('cache-disk-bar');
    if(db){db.style.width=dPct+'%';db.style.background=pctCol(dPct);}
    txt('cache-disk-detail', fmtB(data.cache.bytes_used)+' / '+fmtB(data.cache.bytes_total));

    const rPct = data.cache.ram_cache_total_bytes>0 ? data.cache.ram_cache_bytes_used/data.cache.ram_cache_total_bytes*100 : 0;
    txt('cache-ram-pct', rPct.toFixed(1)+'%');
    const rb = document.getElementById('cache-ram-bar');
    if(rb){rb.style.width=rPct+'%';rb.style.background=pctCol(rPct);}
    txt('cache-ram-detail', fmtB(data.cache.ram_cache_bytes_used)+' / '+fmtB(data.cache.ram_cache_total_bytes));

    // Details
    txt('bw-client-total', fmtB(uaB));
    txt('bw-origin-total', fmtB(osB));
    txt('dns-total', fmtN(data.dns.total_lookups));
    txt('dns-success-rate', data.dns.total_lookups>0 ? (data.dns.lookup_successes/data.dns.total_lookups*100).toFixed(1)+'%' : '--');
    txt('hostdb-total', fmtN(data.hostdb.total_lookups));
    txt('hostdb-hit-rate', data.hostdb.total_lookups>0 ? (data.hostdb.total_hits/data.hostdb.total_lookups*100).toFixed(1)+'%' : '--');
    txt('ci-stripes', data.cache.stripes);
    txt('ci-dirwrap', fmtN(data.cache.directory_wrap));
    txt('ci-dirent-used', fmtN(data.cache.direntries_used));
    txt('ci-dirent-total', fmtN(data.cache.direntries_total));
    txt('ci-read-active', data.cache.read_active);
    txt('ci-write-active', data.cache.write_active);
    txt('err-abort', fmtN(data.errors.client_abort));
    txt('err-connect', fmtN(data.errors.connect_fail));

    prev = data;
    prevTime = now;
  }

  let errCount = 0;
  function poll() {
    fetch('__api/stats')
      .then(r => { if(!r.ok) throw new Error(r.status); return r.json(); })
      .then(data => {
        errCount=0;
        document.getElementById('error-banner').style.display='none';
        update(data);
      })
      .catch(e => {
        errCount++;
        const b=document.getElementById('error-banner');
        b.textContent='Failed to fetch stats ('+e.message+') - retrying...';
        b.style.display=errCount>=2?'block':'none';
      });
  }
  poll();
  setInterval(poll, POLL);
})();
</script>
</body>
</html>
)HTMLRAW");
}
#endif

// ---- Remap Plugin Interface ----

TSReturnCode
TSRemapInit(TSRemapInterface * /* api_info */, char * /* errbuf */, int /* errbuf_size */)
{
  PluginStartTime = time(nullptr);

  if (TSStatFindName("dashboard.response_bytes", &StatCountBytes) == TS_ERROR) {
    StatCountBytes = TSStatCreate("dashboard.response_bytes", TS_RECORDDATATYPE_COUNTER, TS_STAT_NON_PERSISTENT, TS_STAT_SYNC_SUM);
  }

  if (TSStatFindName("dashboard.response_count", &StatCountResponses) == TS_ERROR) {
    StatCountResponses =
      TSStatCreate("dashboard.response_count", TS_RECORDDATATYPE_COUNTER, TS_STAT_NON_PERSISTENT, TS_STAT_SYNC_COUNT);
  }

  VDEBUG("plugin initialized");
  return TS_SUCCESS;
}

TSRemapStatus
TSRemapDoRemap(void * /* ih */, TSHttpTxn rh, TSRemapRequestInfo *rri)
{
  const TSHttpStatus txnstat = TSHttpTxnStatusGet(rh);
  if (txnstat != TS_HTTP_STATUS_NONE && txnstat != TS_HTTP_STATUS_OK) {
    return TSREMAP_NO_REMAP;
  }

  // Extract path from request URL
  int         path_len = 0;
  const char *path     = TSUrlPathGet(rri->requestBufp, rri->requestUrl, &path_len);
  std::string path_str(path ? path : "", path_len);

  // Determine request type
  DashboardRequest *req = new DashboardRequest;

  if (path_str.find("__api/stats") != std::string::npos) {
    req->request_type = RequestType::JSON;
    req->mimeType     = "application/json";
    req->body         = build_stats_json();
  } else {
    req->request_type = RequestType::HTML;
    req->mimeType     = "text/html; charset=utf-8";
    req->body         = build_dashboard_html();
  }

  req->nbytes     = req->body.size();
  req->statusCode = 200;

  // Disable caching for dashboard responses
  TSHttpTxnConfigIntSet(rh, TS_CONFIG_HTTP_CACHE_HTTP, 0);

  DashboardSetupIntercept(req, rh);

  return TSREMAP_NO_REMAP;
}

TSReturnCode
TSRemapNewInstance(int argc, char *argv[], void **ih, char * /* errbuf */, int /* errbuf_size */)
{
  // argv[0] is "from" URL, argv[1] is "to" URL, argv[2+] are plugin args
  if (argc > 2 && argv[2]) {
    DashboardHtmlPath = argv[2];
    VDEBUG("dashboard HTML path: %s", DashboardHtmlPath.c_str());
  }
  *ih = nullptr;
  return TS_SUCCESS;
}

void
TSRemapDeleteInstance(void * /* ih */)
{
}
