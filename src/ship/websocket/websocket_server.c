/*
 * Copyright 2025 NIBE AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/**
 * @file
 * @brief Websocket Wsi implementation
 */

#include "src/ship/websocket/websocket_server.h"
#include "src/ship/api/http_server_interface.h"
#include "src/ship/websocket/websocket.h"
#include "src/ship/websocket/websocket_debug.h"
#include "src/ship/websocket/websocket_internal.h"
#include "src/common/eebus_thread/eebus_thread.h"

/** Longest a destroyed websocket waits for its pending close to be flushed */
static const uint32_t kCloseFlushTimeoutMs = 2000;
static const uint32_t kCloseFlushPollMs    = 10;

typedef struct WebsocketServer WebsocketServer;

struct WebsocketServer {
  /** Implements the Websocket Interface */
  Websocket obj;

  HttpServerObject* server;
};

#define WEBSOCKET_SERVER(obj) ((WebsocketServer*)(obj))

static void Destruct(WebsocketObject* self);
static void WebsocketServerClose(WebsocketObject* self, int32_t close_code, const char* reason);

static const WebsocketInterface websocket_server_methods = {
    .destruct        = Destruct,
    .write           = WebsocketWrite,
    .close           = WebsocketServerClose,
    .is_closed       = WebsocketIsClosed,
    .get_close_error = WebsocketGetCloseError,
    .schedule_write  = WebsocketScheduleWrite,
};

static EebusError WebsocketServerConstruct(
    WebsocketServer* self,
    HttpServerObject* srv,
    struct lws* wsi,
    WebsocketCallback cb,
    void* ctx
);

EebusError WebsocketServerConstruct(
    WebsocketServer* self,
    HttpServerObject* srv,
    struct lws* wsi,
    WebsocketCallback cb,
    void* ctx
) {
  EebusError ret = WebsocketConstruct(WEBSOCKET(self), cb, ctx);
  // Override "virtual functions table"
  WEBSOCKET_INTERFACE(self) = &websocket_server_methods;

  if (ret != kEebusErrorOk) {
    return ret;
  }

  self->server         = srv;
  WEBSOCKET(self)->wsi = wsi;

  return kEebusErrorOk;
}

void Destruct(WebsocketObject* self) {
  WebsocketServer* const wss = WEBSOCKET_SERVER(self);

  Websocket* const ws = WEBSOCKET(self);

  // A pending close belongs to the LWS thread until it reports the connection closed. Give it
  // time to flush, then detach the connection from this object if it never got there.
  if (ws->close_pending) {
    for (uint32_t waited_ms = 0; !ws->close_done && (waited_ms < kCloseFlushTimeoutMs);
         waited_ms += kCloseFlushPollMs) {
      EebusThreadUsleep((int32_t)(kCloseFlushPollMs * 1000));
    }

    if (!ws->close_done && (wss->server != NULL)) {
      HttpServerUnbindWsi(wss->server, ws->wsi);
    }
  }

  ws->wsi = NULL;

  wss->server = NULL;

  WebsocketDestruct(WEBSOCKET_OBJECT(ws));
}

WebsocketObject* WebsocketServerOpen(HttpServerObject* srv, struct lws* wsi, WebsocketCallback cb, void* ctx) {
  WebsocketServer* const wss = (WebsocketServer*)EEBUS_MALLOC(sizeof(WebsocketServer));

  if (wss == NULL) {
    return NULL;
  }

  const EebusError ret = WebsocketServerConstruct(wss, srv, wsi, cb, ctx);
  if (ret != kEebusErrorOk) {
    WEBSOCKET_DEBUG_PRINTF("%s(), constructing websocket failed\n", __func__);
    WebsocketDelete(WEBSOCKET_OBJECT(wss));
    return NULL;
  }

  lws_set_wsi_user(wsi, wss);

  return WEBSOCKET_OBJECT(wss);
}

void WebsocketServerClose(WebsocketObject* self, int32_t close_code, const char* reason) {
  WebsocketServer* const wss = WEBSOCKET_SERVER(self);
  Websocket* const ws        = WEBSOCKET(self);

  // The frames queued just before a close (an SME abort, a protocol handshake error, a close
  // announcement) are what tell the peer why. Keep the connection bound so the LWS thread writes
  // them out and then closes the socket itself, instead of dropping them and leaving it open.
  EEBUS_MUTEX_LOCK(ws->wr_mutex);
  if (ws->close_pending) {
    // Already closing: a second close must not cut short the flush in progress
    EEBUS_MUTEX_UNLOCK(ws->wr_mutex);
    return;
  }

  const bool defer = (ws->wsi != NULL) && !ws->is_closed;
  if (defer) {
    ws->close_error   = close_code;
    ws->is_closed     = true;
    ws->close_pending = true;
    // The owner stops listening once it closes; nothing received from here on is for it
    ws->callback = NULL;
  }
  EEBUS_MUTEX_UNLOCK(ws->wr_mutex);

  if (!defer) {
    HttpServerUnbindWsi(wss->server, ws->wsi);
    WebsocketClose(self, close_code, reason);
  }
}

void WebsocketServerOnClosed(WebsocketObject* self) {
  WebsocketServer* const wss = WEBSOCKET_SERVER(self);
  Websocket* const ws        = WEBSOCKET(self);

  EEBUS_MUTEX_LOCK(ws->wr_mutex);
  const bool closed_locally = ws->close_pending;
  EEBUS_MUTEX_UNLOCK(ws->wr_mutex);

  HttpServerUnbindWsi(wss->server, ws->wsi);
  WebsocketClose(self, closed_locally ? ws->close_error : 0, "");

  if (closed_locally) {
    ws->close_done = true;
    return;
  }

  WebsocketOnClose(self);
}
