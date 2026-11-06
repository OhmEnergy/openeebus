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

#include <stdbool.h>
#include <string.h>

#include "node_connection_container.h"
#include "node_connection_internal.h"
#include "ship_node_internal.h"
#include "src/common/eebus_arguments.h"
#include "src/common/eebus_device_info.h"
#include "src/common/eebus_malloc.h"
#include "src/common/eebus_mutex/eebus_mutex.h"
#include "src/common/eebus_queue/eebus_queue.h"
#include "src/common/eebus_thread/eebus_thread.h"
#include "src/common/eebus_timer/eebus_timer.h"
#include "src/common/service_details.h"
#include "src/common/string_util.h"
#include "src/common/vector.h"
#include "src/ship/api/http_server_interface.h"
#include "src/ship/api/ship_node_interface.h"
#include "src/ship/api/ship_node_reader_interface.h"
#include "src/ship/api/tls_certificate_interface.h"
#include "src/ship/mdns/ship_mdns.h"
#include "src/ship/ship_connection/ship_connection.h"
#include "src/ship/ship_connection/ship_connection_trust.h"
#include "src/ship/websocket/http_server.h"
#include "src/ship/websocket/websocket_client_creator.h"

/** Set SHIP_NODE_DEBUG 1 to enable debug prints */
#ifndef SHIP_NODE_DEBUG
#define SHIP_NODE_DEBUG 0
#endif

/** Ship node debug printf(), enabled whith SHIP_NODE_DEBUG = 1 */
#if SHIP_NODE_DEBUG
#define SHIP_NODE_DEBUG_PRINTF(fmt, ...) DebugPrintf(fmt, ##__VA_ARGS__)
#else
#define SHIP_NODE_DEBUG_PRINTF(fmt, ...)
#endif  // SHIP_NODE_DEBUG

enum ShipNodeQueueMsgType {
  kShipNodeQueueMsgTypeCancel,
  kShipNodeQueueMsgTypeMdnsEntriesFound,
  kShipNodeQueueMsgTypeShipConnectionClosed,
  kShipNodeQueueMsgTypeShipUnregisterSki,
  kShipNodeQueueMsgTypeShipRegisterSki,
  kShipNodeQueueMsgTypeShipCancelPairingSki,
  kShipNodeQueueMsgTypeRetryConnectionForSki,
  kShipNodeQueueMsgTypePromoteFingerprint,
  kShipNodeQueueMsgTypeApprovePendingSki,
  kShipNodeQueueMsgTypeRevokePairingFingerprint,
  kShipNodeQueueMsgTypeCloseDoubleConnection,
  kShipNodeQueueMsgTypeDoubleConnectionTimeout,
};

/**
 * SHIP 12.2.3: how long the node with the smaller SKI waits for the peer to
 * close one of two connections before it closes the older one itself.
 */
static const uint32_t kDoubleConnectionTimeoutMs = 3000;

typedef enum ShipNodeQueueMsgType ShipNodeQueueMsgType;

/** How registration of a peer's certificate fingerprint was authorized. */
typedef enum {
  kPeerTrustConfigured,
  kPeerTrustFromPairingRequest,
} PeerTrustSource;

typedef struct ShipNodeQueueMessage ShipNodeQueueMessage;

struct ShipNodeQueueMessage {
  ShipNodeQueueMsgType type;
  ShipConnectionObject* ship_connection;
  bool had_error;
  bool is_trusted;
  char* ski;
  uint64_t approval_id;
};

static void Destruct(InfoProviderObject* self);
static bool IsRemoteServiceForSkiPaired(InfoProviderObject* self, const char* ski);
static bool ShipNodeAcceptPendingTrust(ShipConnectionObject* sc, uint64_t approval_id, void* ctx);
static void ShipNodeDiscardPendingTrust(ShipNode* self, ShipConnectionObject* sc, uint64_t approval_id);
static void HandleConnectionClosed(InfoProviderObject* self, ShipConnectionObject* sc, bool had_error);
static void ReportServiceShipId(InfoProviderObject* self, const char* service_id, const char* ship_id);
static bool IsWaitingForTrustAllowed(InfoProviderObject* self, const char* ski);
static void HandleShipStateUpdate(InfoProviderObject* self, const char* ski, SmeState state, const char* err);
static DataReaderObject* SetupRemoteDevice(InfoProviderObject* self, const char* ski, DataWriterObject* data_writer);
static void Start(ShipNodeObject* self);
static void Stop(ShipNodeObject* self);
static void RegisterRemoteSki(ShipNodeObject* self, const char* ski, bool is_trusted);
static void RegisterRemoteFingerprint(ShipNodeObject* self, const char* fingerprint);
static EebusError
RegisterRemoteFingerprintWithShipId(ShipNodeObject* self, const char* ship_id, const char* fingerprint);
static EebusError
ShipNodeRegisterPeerTrust(ShipNode* self, const char* ship_id, const char* fingerprint, PeerTrustSource trust_source);
static ShipPairingObject* GetShipPairing(ShipNodeObject* self);
static EebusError AnnounceShipPairingRequest(ShipNodeObject* self, const ShipPairingEntry* entry);
static void ShipNodeOnPairingEntriesFoundCallback(Vector* found_entries, void* ctx);
static void ShipNodeOnPairingEnabledCallback(bool enabled, void* ctx);
static bool ShipNodeIsPairingMessageExchangeAvailable(void* ctx);
static void UnregisterRemoteSki(ShipNodeObject* self, const char* ski);
static void CancelPairingWithSki(ShipNodeObject* self, const char* ski);
static void ApprovePendingHandshakeWithSki(ShipNodeObject* self, const char* ski);
static uint32_t GetPendingWaitingMsWithSki(ShipNodeObject* self, const char* ski);
static void ShipNodeUnregisterSki(ShipNodeObject* self, const char* ski);
static void ShipNodeCancelPairingSki(ShipNodeObject* self, const char* ski);
static void ShipNodeRegisterSki(ShipNodeObject* self, const char* ski, bool is_trusted);
static void ShipNodePromoteFingerprint(ShipNode* self);
static void ShipNodeRevokePairingFingerprint(ShipNode* self, const char* fingerprint);

static const ShipNodeInterface ship_node_methods = {
    .info_provider_interface = {
        .destruct                         = Destruct,
        .is_remote_service_for_ski_paired = IsRemoteServiceForSkiPaired,
        .handle_connection_closed         = HandleConnectionClosed,
        .report_service_ship_id           = ReportServiceShipId,
        .is_waiting_for_trust_allowed     = IsWaitingForTrustAllowed,
        .handle_ship_state_update         = HandleShipStateUpdate,
        .setup_remote_device              = SetupRemoteDevice,
    },

    .start                              = Start,
    .stop                               = Stop,
    .register_remote_ski                = RegisterRemoteSki,
    .unregister_remote_ski              = UnregisterRemoteSki,
    .cancel_pairing_with_ski            = CancelPairingWithSki,
    .approve_pending_handshake_with_ski = ApprovePendingHandshakeWithSki,
    .get_pending_waiting_ms_with_ski    = GetPendingWaitingMsWithSki,
    .register_remote_fingerprint        = RegisterRemoteFingerprint,
    .get_ship_pairing                   = GetShipPairing,
    .announce_ship_pairing_request      = AnnounceShipPairingRequest,
    .register_remote_fingerprint_with_ship_id = RegisterRemoteFingerprintWithShipId,
};

static void ShipNodeConstruct(
    ShipNode* self,
    const char* ski,
    const char* role,
    const EebusDeviceInfo* device_info,
    const char* service_name,
    int port,
    const TlsCertificateObject* tsl_certificate,
    ShipNodeReaderObject* ship_node_reader,
    ServiceDetails* local_service_details,
    EebusTrustMode trust_mode
);

static void ShipNodeOnMdnsEntriesFoundCallback(Vector* found_entries, void* ctx);
static bool SkiMatches(const char* ski_a, const char* ski_b);
static void CloseShipConnection(ShipNode* self, ShipConnectionObject* sc, bool had_error);
static bool ShipNodeFindServiceForPeer(ShipNode* self, NodeConnectionObject* nc, MdnsEntry* found_entry);
static void ShipNodeConnectToPendingSki(ShipNode* self, const char* ski);
static void ShipNodeConnectToAllPendingSkis(ShipNode* self);
static void* ShipNodeConnectionLoop(void* ctx);
static int
ShipNodeOnWebsocketServerConnectionCallback(const char* ski, WebsocketCreatorObject* websocket_creator, void* ctx);
static bool ShipNodeIsClientSupported(ShipNode* self);
static bool ShipNodeIsServerSupported(ShipNode* self);
static void ShipNodeRetryTimerCallback(void* ctx);
static void ShipNodeDoubleConnectionTimerCallback(void* ctx);
static void ShipNodeResolveDoubleConnection(ShipNode* self, const char* remote_ski, ShipConnectionObject* older);
static void ShipNodeCloseDoubleConnection(ShipNode* self, ShipConnectionObject* sc);
static void ShipNodeCloseAllDoubleConnections(ShipNode* self);

static void ShipNodeQueueMsgDeallocator(void* msg) {
  if (msg == NULL) {
    return;
  }

  ShipNodeQueueMessage* queue_msg = (ShipNodeQueueMessage*)msg;
  StringDelete(queue_msg->ski);
  queue_msg->ski = NULL;
}

static void ShipNodePostConnectionClose(ShipNode* sn, ShipConnectionObject* sc, bool had_error) {
  ShipNodeQueueMessage queue_msg = {
      .type            = kShipNodeQueueMsgTypeShipConnectionClosed,
      .ship_connection = sc,
      .had_error       = had_error,
      .ski             = NULL,
  };
  EEBUS_QUEUE_SEND(sn->msg_queue, &queue_msg, kTimeoutInfinite);
}

static void ShipNodeRetryTimerCallback(void* ctx) {
  NodeConnectionObject* const nc = (NodeConnectionObject*)ctx;

  ShipNode* const sn = NODE_CONNECTION_GET_OWNER(nc);
  if (sn->cancel) {
    return;
  }

  ShipNodeQueueMessage queue_msg = {
      .type            = kShipNodeQueueMsgTypeRetryConnectionForSki,
      .ship_connection = NULL,
      .had_error       = false,
      .ski             = StringCopy(NODE_CONNECTION_GET_SKI(nc)),
  };
  EEBUS_QUEUE_SEND(sn->msg_queue, &queue_msg, kTimeoutInfinite);
}

static void ShipNodeDoubleConnectionTimerCallback(void* ctx) {
  ShipNode* const sn = (ShipNode*)ctx;
  if (sn->cancel) {
    return;
  }

  ShipNodeQueueMessage queue_msg = {.type = kShipNodeQueueMsgTypeDoubleConnectionTimeout};
  EEBUS_QUEUE_SEND(sn->msg_queue, &queue_msg, kTimeoutInfinite);
}

void ShipNodeConstruct(
    ShipNode* self,
    const char* ski,
    const char* role,
    const EebusDeviceInfo* device_info,
    const char* service_name,
    int port,
    const TlsCertificateObject* tsl_certificate,
    ShipNodeReaderObject* ship_node_reader,
    ServiceDetails* local_service_details,
    EebusTrustMode trust_mode
) {
  // Override "virtual function table"
  SHIP_NODE_INTERFACE(self) = &ship_node_methods;

  self->mdns = ShipMdnsCreate(ski, device_info, service_name, port, ShipNodeOnMdnsEntriesFoundCallback, self);

  static const size_t kQueueMaxMsg = 20;

  self->msg_queue = EebusQueueCreate(kQueueMaxMsg, sizeof(ShipNodeQueueMessage), ShipNodeQueueMsgDeallocator);

  self->mdns_entries          = VectorCreateWithDeallocator(MdnsEntryDeallocator);
  self->mutex                 = EebusMutexCreate();
  self->search_for_remote_ski = false;
  self->cancel                = false;
  self->next_approval_id      = 0;
  self->connection_thread     = NULL;

  self->connections           = NodeConnectionContainerCreate();
  self->trust_mode            = trust_mode;
  self->remote_fingerprint    = NULL;
  self->ship_node_reader      = ship_node_reader;
  self->tsl_certificate       = tsl_certificate;
  self->local_service_details = local_service_details;

  self->local_ski               = StringCopy(ski);
  self->double_connection_timer = EebusTimerCreate(ShipNodeDoubleConnectionTimerCallback, self);

  self->ship_pairing = ShipPairingCreate(local_service_details->ship_id, tsl_certificate);
  if (self->ship_pairing != NULL) {
    SHIP_PAIRING_SET_ENABLED_CALLBACK(self->ship_pairing, ShipNodeOnPairingEnabledCallback, self);
    ShipPairingSetMessageExchangeAvailableCallback(self->ship_pairing, ShipNodeIsPairingMessageExchangeAvailable, self);
  }

  self->http_server = HttpServerCreate(port, tsl_certificate, ShipNodeOnWebsocketServerConnectionCallback, self);

  if (strcmp(role, "server") == 0) {
    self->role = kShipRoleServer;
  } else if (strcmp(role, "client") == 0) {
    self->role = kShipRoleClient;
  } else {
    self->role = kShipRoleAuto;
  }
}

ShipNodeObject* ShipNodeCreate(
    const char* ski,
    const char* role,
    const EebusDeviceInfo* device_info,
    const char* service_name,
    int port,
    const TlsCertificateObject* tls_certificate,
    ShipNodeReaderObject* ship_node_reader,
    ServiceDetails* local_service_details,
    EebusTrustMode trust_mode
) {
  ShipNode* const sn = (ShipNode*)EEBUS_MALLOC(sizeof(ShipNode));

  ShipNodeConstruct(
      sn,
      ski,
      role,
      device_info,
      service_name,
      port,
      tls_certificate,
      ship_node_reader,
      local_service_details,
      trust_mode
  );

  return SHIP_NODE_OBJECT(sn);
}

void Destruct(InfoProviderObject* self) {
  ShipNode* const sn = SHIP_NODE(self);

  SHIP_NODE_DEBUG_PRINTF("ShipNode::%s(): begin\n", __func__);

  ShipPairingDelete(sn->ship_pairing);
  sn->ship_pairing = NULL;
  StringDelete(sn->remote_fingerprint);
  sn->remote_fingerprint = NULL;

  if (sn->double_connection_timer != NULL) {
    EEBUS_TIMER_STOP(sn->double_connection_timer);
    EebusTimerDelete(sn->double_connection_timer);
    sn->double_connection_timer = NULL;
  }

  StringDelete(sn->local_ski);
  sn->local_ski = NULL;

  if (sn->mdns != NULL) {
    SHIP_MDNS_DESTRUCT(sn->mdns);
    EEBUS_FREE(sn->mdns);
    sn->mdns = NULL;
  }

  if (sn->mdns_entries != NULL) {
    VectorFreeElements(sn->mdns_entries);
    VectorDestruct(sn->mdns_entries);
    EEBUS_FREE(sn->mdns_entries);
    sn->mdns_entries = NULL;
  }

  EebusMutexDelete(sn->mutex);
  sn->mutex = NULL;

  if (sn->http_server != NULL) {
    HttpServerDelete(sn->http_server);
    sn->http_server = NULL;
  }

  // Stop and delete every active connection before releasing the table
  for (size_t i = 0; i < NODE_CONNECTION_CONTAINER_GET_SIZE(sn->connections); ++i) {
    NodeConnectionObject* nc    = NODE_CONNECTION_CONTAINER_GET_WITH_INDEX(sn->connections, i);
    ShipConnectionObject* older = NODE_CONNECTION_RELEASE_SUPERSEDED_CONNECTION(nc);
    ShipConnectionObject* sc    = NODE_CONNECTION_RELEASE_SHIP_CONNECTION(nc);
    if (older != NULL) {
      SHIP_CONNECTION_STOP(older);
      ShipConnectionDelete(older);
    }

    if (sc != NULL) {
      SHIP_CONNECTION_STOP(sc);
      ShipConnectionDelete(sc);
    }
  }

  NodeConnectionContainerDelete(sn->connections);
  sn->connections = NULL;

  EebusQueueDelete(sn->msg_queue);
  sn->msg_queue = NULL;

  SHIP_NODE_DEBUG_PRINTF("ShipNode::%s(): end\n", __func__);
}

void ShipNodeOnMdnsEntriesFoundCallback(Vector* found_entries, void* ctx) {
  ShipNode* const sn = (ShipNode*)ctx;

  if (sn->cancel) {
    return;
  }

  if (found_entries == NULL) {
    return;
  }

  EEBUS_MUTEX_LOCK(sn->mutex);
  VectorFreeElements(sn->mdns_entries);
  VectorMove(sn->mdns_entries, found_entries);
  EEBUS_FREE(found_entries);
  EEBUS_MUTEX_UNLOCK(sn->mutex);

  sn->search_for_remote_ski = true;
  if (sn->ship_node_reader != NULL) {
    SHIP_NODE_READER_ON_REMOTE_SERVICES_UPDATE(sn->ship_node_reader, sn->mdns_entries);
  }

  if (ShipNodeIsClientSupported(sn)) {
    ShipNodeQueueMessage queue_msg = {
        .type            = kShipNodeQueueMsgTypeMdnsEntriesFound,
        .ship_connection = NULL,
        .had_error       = false,
        .ski             = NULL,
    };

    EEBUS_QUEUE_SEND(sn->msg_queue, &queue_msg, kTimeoutInfinite);
  }
}

bool IsRemoteServiceForSkiPaired(InfoProviderObject* self, const char* ski) {
  ShipNode* const sn = SHIP_NODE(self);
  EEBUS_MUTEX_LOCK(sn->mutex);
  NodeConnectionObject* nc = NODE_CONNECTION_CONTAINER_FIND_WITH_SKI(sn->connections, ski);
  const bool paired        = (nc != NULL) && NODE_CONNECTION(nc)->is_trusted;
  EEBUS_MUTEX_UNLOCK(sn->mutex);
  return paired;
}

static bool ShipNodeAcceptPendingTrust(ShipConnectionObject* sc, uint64_t approval_id, void* ctx) {
  ShipNode* const sn = (ShipNode*)ctx;
  bool accepted      = false;
  EEBUS_MUTEX_LOCK(sn->mutex);
  NodeConnectionObject* obj = NODE_CONNECTION_CONTAINER_FIND_WITH_SHIP_CONNECTION(sn->connections, sc);

  NodeConnection* nc = (obj == NULL) ? NULL : NODE_CONNECTION(obj);
  if (!sn->cancel && (nc != NULL)) {
    if (approval_id == 0) {
      // addCu establishes certificate trust independently of this handshake.
      accepted = nc->is_trusted;
    } else if (NodeConnectionHasPendingApproval(nc, sc, approval_id)) {
      nc->pending_approval_id = 0;
      nc->is_trusted          = true;
      nc->provisional         = false;
      accepted                = true;
    }
  }

  EEBUS_MUTEX_UNLOCK(sn->mutex);

  return accepted;
}

static void ShipNodeDiscardPendingTrust(ShipNode* self, ShipConnectionObject* sc, uint64_t approval_id) {
  EEBUS_MUTEX_LOCK(self->mutex);
  NodeConnectionObject* obj = NODE_CONNECTION_CONTAINER_FIND_WITH_SHIP_CONNECTION(self->connections, sc);

  NodeConnection* nc = (obj == NULL) ? NULL : NODE_CONNECTION(obj);
  if (NodeConnectionHasPendingApproval(nc, sc, approval_id)) {
    nc->pending_approval_id = 0;
  }

  EEBUS_MUTEX_UNLOCK(self->mutex);
}

void CloseShipConnection(ShipNode* self, ShipConnectionObject* sc, bool had_error) {
  UNUSED(had_error);

  if (sc == NULL) {
    return;
  }

  // Scan by pointer identity — never dereferences sc, safe even for dangling
  // pointers from a double-close event on a superseded connection.
  EEBUS_MUTEX_LOCK(self->mutex);

  char* ski                   = NULL;
  uint32_t retry_delay        = 0;
  bool discard                = false;
  bool reconnect              = false;
  bool notify_disconnected    = true;
  ShipConnectionObject* older = NULL;
  NodeConnectionObject* nc    = NODE_CONNECTION_CONTAINER_FIND_WITH_SHIP_CONNECTION(self->connections, sc);
  if (nc != NULL) {
    NodeConnection* const peer = NODE_CONNECTION(nc);
    ski                        = StringCopy(NODE_CONNECTION_GET_SKI(nc));
    if (peer->superseded == sc) {
      // One of two connections to the peer closed and the other carries on. Its
      // remote device goes only if it had one and the other has none yet.
      notify_disconnected = peer->superseded_handshake_complete && !peer->handshake_complete;
      NODE_CONNECTION_RELEASE_SUPERSEDED_CONNECTION(nc);
    } else if ((peer->superseded != NULL) && !peer->handshake_complete) {
      // The newer connection closed before data exchange: the older one carries on
      notify_disconnected = false;
      NODE_CONNECTION_RESTORE_SUPERSEDED_CONNECTION(nc);
    } else {
      older       = NODE_CONNECTION_RELEASE_SUPERSEDED_CONNECTION(nc);
      discard     = peer->provisional && !peer->is_trusted;
      retry_delay = NODE_CONNECTION_ON_CONNECTION_CLOSED(nc);
      reconnect   = !self->cancel && !discard && (retry_delay == 0);
      if (discard) {
        NODE_CONNECTION_CONTAINER_REMOVE_WITH_SKI(self->connections, NODE_CONNECTION_GET_SKI(nc));
      } else if (!self->cancel && (retry_delay > 0)) {
        NODE_CONNECTION_SCHEDULE_RETRY(nc, retry_delay);
      }
    }
  }

  EEBUS_MUTEX_UNLOCK(self->mutex);

  if (nc != NULL) {
    SHIP_CONNECTION_STOP(sc);
    if (older != NULL) {
      // The peer stays trusted, so the close gives no reason rather than the
      // removed connection a stop announces.
      SHIP_CONNECTION_CLOSE_CONNECTION(older, true, 0, kShipCloseReasonUnspecific);
      SHIP_CONNECTION_STOP(older);
    }

    SHIP_NODE_DEBUG_PRINTF("%s(), connection closed\n", __func__);
    if (notify_disconnected) {
      SHIP_NODE_READER_ON_REMOTE_SKI_DISCONNECTED(self->ship_node_reader, ski);
    }

    ShipConnectionDelete(sc);
    ShipConnectionDelete(older);

    if (reconnect && (ski != NULL)) {
      ShipNodeConnectToPendingSki(self, ski);
    }
  }
  StringDelete(ski);
  // else: orphaned/double close — sc must NOT be dereferenced
}

static bool ShipNodeIsCurrentPairingPeer(const ShipNode* self, const NodeConnection* peer) {
  return (peer != NULL) && peer->is_trusted && peer->trusted_by_pairing
         && ShipNodeFingerprintMatches(peer->expected_fingerprint, self->remote_fingerprint);
}

static bool ShipNodeIsPairingMessageExchangeAvailable(void* ctx) {
  ShipNode* const sn = (ShipNode*)ctx;
  bool available     = false;
  EEBUS_MUTEX_LOCK(sn->mutex);
  for (size_t i = 0; (i < NODE_CONNECTION_CONTAINER_GET_SIZE(sn->connections)) && !available; ++i) {
    const NodeConnection* const peer = NODE_CONNECTION(NODE_CONNECTION_CONTAINER_GET_WITH_INDEX(sn->connections, i));
    available = (peer->connection != NULL) && peer->handshake_complete && ShipNodeIsCurrentPairingPeer(sn, peer);
  }

  EEBUS_MUTEX_UNLOCK(sn->mutex);
  return available;
}

void HandleConnectionClosed(InfoProviderObject* self, ShipConnectionObject* sc, bool had_error) {
  ShipNode* const sn = SHIP_NODE(self);

  EEBUS_MUTEX_LOCK(sn->mutex);
  NodeConnectionObject* nc    = NODE_CONNECTION_CONTAINER_FIND_WITH_SHIP_CONNECTION(sn->connections, sc);
  bool current_pairing_closed = false;
  if ((nc != NULL) && (NODE_CONNECTION(nc)->connection == sc)) {
    current_pairing_closed
        = NODE_CONNECTION(nc)->handshake_complete && ShipNodeIsCurrentPairingPeer(sn, NODE_CONNECTION(nc));
    NODE_CONNECTION(nc)->pending_approval_id = 0;
  }

  EEBUS_MUTEX_UNLOCK(sn->mutex);

  if (sn->cancel) {
    return;
  }

  // Section 4.3.1, item a.i: after the current devZ's established connection
  // closes, wait 15 minutes before processing addCu requests again.
  // NotifyMessageExchange() resets the timer from this last moment of
  // communication availability. Failed handshakes must not reset it.
  if (current_pairing_closed && (sn->ship_pairing != NULL)) {
    SHIP_PAIRING_NOTIFY_MESSAGE_EXCHANGE(sn->ship_pairing);
  }

  ShipNodePostConnectionClose(sn, sc, had_error);
}

void ReportServiceShipId(InfoProviderObject* self, const char* service_id, const char* ship_id) {
  ShipNode* const sn = SHIP_NODE(self);
  EEBUS_MUTEX_LOCK(sn->mutex);
  NodeConnectionObject* nc = NODE_CONNECTION_CONTAINER_FIND_WITH_SKI(sn->connections, service_id);
  if ((nc != NULL) && (NODE_CONNECTION(nc)->ship_id == NULL)) {
    NODE_CONNECTION(nc)->ship_id = StringCopy(ship_id);
  }

  EEBUS_MUTEX_UNLOCK(sn->mutex);
  SHIP_NODE_READER_ON_SHIP_ID_UPDATE(sn->ship_node_reader, service_id, ship_id);
}

bool IsWaitingForTrustAllowed(InfoProviderObject* self, const char* ski) {
  const ShipNode* const sn = SHIP_NODE(self);
  return SHIP_NODE_READER_IS_WAITING_FOR_TRUST_ALLOWED(sn->ship_node_reader, ski);
}

// Caller holds the node mutex. A state report carries only the SKI, so the
// connection that reached data exchange is told apart by the states of both.
static bool ShipNodeIsSupersededInDataExchange(const NodeConnection* peer) {
  if ((peer->superseded == NULL) || peer->superseded_handshake_complete
      || (SHIP_CONNECTION_GET_SHIP_STATE(peer->superseded, NULL) != kDataExchange)) {
    return false;
  }

  return (peer->connection == NULL) || peer->handshake_complete
         || (SHIP_CONNECTION_GET_SHIP_STATE(peer->connection, NULL) != kDataExchange);
}

// Runs on the connection thread of a dialled connection once the peer answered
// its CMI message, which follows the TLS handshake. SHIP 12.2.3 orders the
// connections to one peer by when their TLS handshake completed.
static void ShipNodeOnClientConnectionEstablished(ShipNode* self, const char* ski) {
  ShipConnectionObject* older = NULL;
  const bool bigger_ski       = ShipNodeHasBiggerSki(self->local_ski, ski);

  EEBUS_MUTEX_LOCK(self->mutex);
  NodeConnectionObject* nc = NODE_CONNECTION_CONTAINER_FIND_WITH_SKI(self->connections, ski);
  if (nc != NULL) {
    NodeConnection* const peer = NODE_CONNECTION(nc);
    // With the bigger SKI the connection set aside is already being closed.
    if (!bigger_ski && (peer->dialed_connection != NULL) && (peer->superseded == peer->dialed_connection)) {
      NODE_CONNECTION_SWAP_SUPERSEDED_CONNECTION(nc);
    }

    if ((peer->dialed_connection != NULL) && (peer->connection == peer->dialed_connection)) {
      older = peer->superseded;
    }
  }

  EEBUS_MUTEX_UNLOCK(self->mutex);

  if (older != NULL) {
    ShipNodeResolveDoubleConnection(self, ski, older);
  }
}

void HandleShipStateUpdate(InfoProviderObject* self, const char* ski, SmeState state, const char* err) {
  UNUSED(err);
  ShipNode* const sn = SHIP_NODE(self);

  SHIP_NODE_READER_ON_SHIP_STATE_UPDATE(sn->ship_node_reader, ski, state);

  if (state == kCmiStateClientEvaluate) {
    ShipNodeOnClientConnectionEstablished(sn, ski);
  }

  if (state == kDataExchange) {
    bool just_completed            = false;
    bool current_pairing_connected = false;
    EEBUS_MUTEX_LOCK(sn->mutex);
    NodeConnectionObject* nc = NODE_CONNECTION_CONTAINER_FIND_WITH_SKI(sn->connections, ski);
    if ((nc != NULL) && ShipNodeIsSupersededInDataExchange(NODE_CONNECTION(nc))) {
      NODE_CONNECTION(nc)->superseded_handshake_complete = true;
    } else if (nc != NULL) {
      just_completed            = NODE_CONNECTION_ON_HANDSHAKE_COMPLETE(nc);
      current_pairing_connected = just_completed && ShipNodeIsCurrentPairingPeer(sn, NODE_CONNECTION(nc));
    }

    EEBUS_MUTEX_UNLOCK(sn->mutex);
    // Section 4.3.1, item b.ii: a successful connection to the current devZ
    // deactivates addCu again if the reactivation interval already elapsed.
    if (current_pairing_connected && (sn->ship_pairing != NULL)) {
      SHIP_PAIRING_NOTIFY_MESSAGE_EXCHANGE(sn->ship_pairing);
    }

    if (just_completed) {
      SHIP_NODE_READER_ON_REMOTE_SKI_CONNECTED(sn->ship_node_reader, ski);
    }
  }
}

DataReaderObject* SetupRemoteDevice(InfoProviderObject* self, const char* ski, DataWriterObject* data_writer) {
  const ShipNode* const sn = SHIP_NODE(self);

  return SHIP_NODE_READER_SETUP_REMOTE_DEVICE(sn->ship_node_reader, ski, data_writer);
}

ShipPairingObject* GetShipPairing(ShipNodeObject* self) {
  return SHIP_NODE(self)->ship_pairing;
}

EebusError AnnounceShipPairingRequest(ShipNodeObject* self, const ShipPairingEntry* entry) {
  ShipNode* const sn = SHIP_NODE(self);

  if (sn->mdns == NULL) {
    return kEebusErrorInit;
  }

  if (entry == NULL) {
    SHIP_MDNS_DEREGISTER_PAIRING_SERVICE(sn->mdns);
    return kEebusErrorOk;
  }

  return SHIP_MDNS_REGISTER_PAIRING_SERVICE(sn->mdns, entry);
}

/**
 * @brief Starts or stops looking for shippairing requests
 *
 * A node that has no secret, or that is already paired and so is no longer
 * processing addCu-requests, would reject every request it was given. Rather
 * than discover and resolve announcements in order to throw them away, it stops
 * asking for them, and starts again if that changes.
 */
void ShipNodeOnPairingEnabledCallback(bool enabled, void* ctx) {
  ShipNode* const sn = (ShipNode*)ctx;

  if (sn->mdns == NULL) {
    return;
  }

  if (enabled) {
    SHIP_MDNS_START_PAIRING_BROWSE(sn->mdns, ShipNodeOnPairingEntriesFoundCallback, sn);
  } else {
    SHIP_MDNS_STOP_PAIRING_BROWSE(sn->mdns);
  }
}

/**
 * @brief Evaluates the shippairing requests a browse turned up
 *
 * Everything discovered arrives here, because only the evaluator can tell which
 * requests are ours and genuine. Section 9 forbids evaluating two at once, and
 * they are taken one at a time from the browsing thread.
 */
void ShipNodeOnPairingEntriesFoundCallback(Vector* found_entries, void* ctx) {
  ShipNode* const sn = (ShipNode*)ctx;

  if ((found_entries == NULL) || (sn == NULL)) {
    return;
  }

  for (size_t i = 0; (i < VectorGetSize(found_entries)) && !sn->cancel; ++i) {
    const ShipPairingEntry* const entry = (const ShipPairingEntry*)VectorGetElement(found_entries, i);
    if ((entry == NULL) || (sn->ship_pairing == NULL)) {
      continue;
    }

    if (SHIP_PAIRING_EVALUATE(sn->ship_pairing, entry) != kShipPairingResultAccepted) {
      continue;
    }

    SHIP_NODE_DEBUG_PRINTF("%s(), accepted a shippairing request from %s\n", __func__, entry->trust_id);

    // Section 10.2: from here the node is recognised by the certificate the
    // request named, since nothing yet knows its SKI.
    RegisterRemoteFingerprint(SHIP_NODE_OBJECT(sn), entry->trust_par);

    const EebusError register_err
        = ShipNodeRegisterPeerTrust(sn, entry->trust_id, entry->trust_par, kPeerTrustFromPairingRequest);
    if (register_err != kEebusErrorOk) {
      SHIP_NODE_DEBUG_PRINTF("%s(), could not configure peer discovery: %d\n", __func__, register_err);
    }

    // Section 10.4: the trust store is the integrator's, so it is told to
    // record the node. Section 10.3 requires any previously paired node to be
    // untrusted at the same time.
    SHIP_NODE_READER_ON_SHIP_PAIRING_ACCEPTED(
        sn->ship_node_reader,
        entry->trust_id,
        entry->trust_par,
        entry->trust_curve
    );
  }

  VectorFreeElements(found_entries);
  VectorDestruct(found_entries);
  EEBUS_FREE(found_entries);
}

static NodeConnectionObject* ShipNodeFindPeerForRegistration(
    ShipNode* sn,
    const char* ship_id,
    const char* fingerprint,
    PeerTrustSource trust_source
) {
  NodeConnectionObject* nc = NODE_CONNECTION_CONTAINER_FIND_WITH_SHIP_ID(sn->connections, ship_id);
  // If the SHIP ID is not stored yet, reuse a trusted entry with the same expected certificate fingerprint.
  if (nc == NULL) {
    nc = NODE_CONNECTION_CONTAINER_FIND_WITH_FINGERPRINT(sn->connections, fingerprint);
  }

  // An accepted pairing request can identify an untrusted incoming peer by the certificate it presented.
  if ((nc == NULL) && (trust_source == kPeerTrustFromPairingRequest)) {
    for (size_t i = 0; i < NODE_CONNECTION_CONTAINER_GET_SIZE(sn->connections); ++i) {
      NodeConnectionObject* candidate = NODE_CONNECTION_CONTAINER_GET_WITH_INDEX(sn->connections, i);
      // Reuse the connection whose presented certificate matches the fingerprint authorized by the request.
      if (ShipNodeFingerprintMatches(NODE_CONNECTION(candidate)->peer_fingerprint, fingerprint)) {
        nc = candidate;
        break;
      }
    }
  }

  // If stored identities did not locate the peer, use discovery to map the SHIP ID to an existing SKI entry.
  if (nc == NULL) {
    for (size_t i = 0; i < VectorGetSize(sn->mdns_entries); ++i) {
      const MdnsEntry* entry = VectorGetElement(sn->mdns_entries, i);
      // The advertised SHIP ID selects the SKI entry to update; it does not authenticate the peer.
      if ((entry->id != NULL) && (strcmp(entry->id, ship_id) == 0)) {
        nc = NODE_CONNECTION_CONTAINER_FIND_WITH_SKI(sn->connections, entry->ski);
        break;
      }
    }
  }

  return nc;
}

// Caller holds the node mutex. Reports any connection to close after registration.
static EebusError ShipNodeCheckPeerRegistration(
    NodeConnectionObject* nc,
    const char* fingerprint,
    PeerTrustSource trust_source,
    ShipConnectionObject** close_connection
) {
  *close_connection = NULL;
  // An active attempt needs special handling when its expected fingerprint is unset or differs from the new one.
  if ((nc != NULL) && NODE_CONNECTION_IS_ATTEMPT_RUNNING(nc)
      && !ShipNodeFingerprintMatches(NODE_CONNECTION(nc)->expected_fingerprint, fingerprint)) {
    // Direct configuration cannot authenticate an attempt already in progress; the caller must stop it first.
    if (trust_source == kPeerTrustConfigured) {
      return kEebusErrorCommunicationBusy;
    }

    // An accepted request can keep the active connection only if its presented certificate matches the request.
    if (!ShipNodeFingerprintMatches(NODE_CONNECTION(nc)->peer_fingerprint, fingerprint)) {
      *close_connection = NODE_CONNECTION(nc)->connection;
    }
  }

  return kEebusErrorOk;
}

static void ShipNodeSchedulePeerConnection(ShipNode* sn, ShipConnectionObject* close_connection) {
  if (close_connection != NULL) {
    // Close the existing connection and retry with the new required certificate fingerprint.
    ShipNodePostConnectionClose(sn, close_connection, false);
  }

  if (ShipNodeIsClientSupported(sn)) {
    ShipNodeQueueMessage msg = {.type = kShipNodeQueueMsgTypeMdnsEntriesFound};
    EEBUS_QUEUE_SEND(sn->msg_queue, &msg, kTimeoutInfinite);
  }
}

/**
 * @brief Configures peer trust and schedules connection actions
 *
 * The SHIP ID locates the peer and the fingerprint authenticates its certificate.
 * Success does not mean a connection has been established.
 */
EebusError
ShipNodeRegisterPeerTrust(ShipNode* sn, const char* ship_id, const char* fingerprint, PeerTrustSource trust_source) {
  uint8_t hash[32];
  if (StringIsEmpty(ship_id) || (strlen(ship_id) > 63) || !StringHexToBytes(fingerprint, hash, sizeof(hash))) {
    return kEebusErrorInputArgument;
  }

  char* id_copy          = StringCopy(ship_id);
  char* fingerprint_copy = StringCopy(fingerprint);
  if ((id_copy == NULL) || (fingerprint_copy == NULL)) {
    StringDelete(id_copy);
    StringDelete(fingerprint_copy);
    return kEebusErrorMemoryAllocate;
  }

  ShipConnectionObject* close_connection = NULL;
  EEBUS_MUTEX_LOCK(sn->mutex);
  NodeConnectionObject* nc = ShipNodeFindPeerForRegistration(sn, ship_id, fingerprint, trust_source);
  const EebusError ret     = ShipNodeCheckPeerRegistration(nc, fingerprint, trust_source, &close_connection);
  if (ret != kEebusErrorOk) {
    EEBUS_MUTEX_UNLOCK(sn->mutex);
    StringDelete(id_copy);
    StringDelete(fingerprint_copy);
    return ret;
  }

  if (nc == NULL) {
    nc = NODE_CONNECTION_CONTAINER_GET_OR_CREATE(sn->connections, NULL, sn, ShipNodeRetryTimerCallback);
  }

  if (nc == NULL) {
    EEBUS_MUTEX_UNLOCK(sn->mutex);
    StringDelete(id_copy);
    StringDelete(fingerprint_copy);
    return kEebusErrorMemoryAllocate;
  }

  NodeConnection* peer = NODE_CONNECTION(nc);
  StringDelete(peer->ship_id);
  StringDelete(peer->expected_fingerprint);
  peer->ship_id              = id_copy;
  peer->expected_fingerprint = fingerprint_copy;
  peer->is_trusted           = true;
  peer->provisional          = false;
  peer->trusted_by_pairing   = peer->trusted_by_pairing || (trust_source == kPeerTrustFromPairingRequest);
  EEBUS_MUTEX_UNLOCK(sn->mutex);

  ShipNodeSchedulePeerConnection(sn, close_connection);
  return kEebusErrorOk;
}

EebusError RegisterRemoteFingerprintWithShipId(ShipNodeObject* self, const char* ship_id, const char* fingerprint) {
  return ShipNodeRegisterPeerTrust(SHIP_NODE(self), ship_id, fingerprint, kPeerTrustConfigured);
}

void RegisterRemoteFingerprint(ShipNodeObject* self, const char* fingerprint) {
  ShipNode* const sn = SHIP_NODE(self);

  EEBUS_MUTEX_LOCK(sn->mutex);
  const bool replacing
      = !StringIsEmpty(sn->remote_fingerprint) && !ShipNodeFingerprintMatches(sn->remote_fingerprint, fingerprint);

  ShipNodeQueueMessage revoke_msg = {
      .type = kShipNodeQueueMsgTypeRevokePairingFingerprint,
      .ski  = replacing ? StringCopy(sn->remote_fingerprint) : NULL,
  };

  if (replacing) {
    for (size_t i = 0; i < NODE_CONNECTION_CONTAINER_GET_SIZE(sn->connections); ++i) {
      NodeConnection* nc = NODE_CONNECTION(NODE_CONNECTION_CONTAINER_GET_WITH_INDEX(sn->connections, i));
      if (nc->trusted_by_pairing && ShipNodeFingerprintMatches(nc->expected_fingerprint, sn->remote_fingerprint)) {
        nc->is_trusted          = false;
        nc->provisional         = true;
        nc->pending_approval_id = 0;
      }
    }
  }

  StringDelete(sn->remote_fingerprint);
  sn->remote_fingerprint = StringCopy(fingerprint);
  EEBUS_MUTEX_UNLOCK(sn->mutex);

  if (revoke_msg.ski != NULL) {
    EEBUS_QUEUE_SEND(sn->msg_queue, &revoke_msg, kTimeoutInfinite);
  }

  ShipNodeQueueMessage queue_msg = {.type = kShipNodeQueueMsgTypePromoteFingerprint};
  EEBUS_QUEUE_SEND(sn->msg_queue, &queue_msg, kTimeoutInfinite);
}

// The SHIP Pairing Service permits one current devZ. Keep classic SKI trust and
// other active connections while withdrawing the previous pairing-derived one.
void ShipNodeRevokePairingFingerprint(ShipNode* sn, const char* fingerprint) {
  size_t i = 0;
  while (true) {
    EEBUS_MUTEX_LOCK(sn->mutex);
    if (i >= NODE_CONNECTION_CONTAINER_GET_SIZE(sn->connections)) {
      EEBUS_MUTEX_UNLOCK(sn->mutex);
      return;
    }

    NodeConnectionObject* nc   = NODE_CONNECTION_CONTAINER_GET_WITH_INDEX(sn->connections, i);
    NodeConnection* connection = NODE_CONNECTION(nc);
    if (!connection->trusted_by_pairing || !ShipNodeFingerprintMatches(connection->expected_fingerprint, fingerprint)) {
      ++i;
      EEBUS_MUTEX_UNLOCK(sn->mutex);
      continue;
    }

    ShipConnectionObject* older = NODE_CONNECTION_RELEASE_SUPERSEDED_CONNECTION(nc);
    ShipConnectionObject* sc    = NODE_CONNECTION_RELEASE_SHIP_CONNECTION(nc);
    // Pairing can trust a peer before its SKI is known, so remove the entry directly.
    NODE_CONNECTION_CONTAINER_REMOVE(sn->connections, nc);
    EEBUS_MUTEX_UNLOCK(sn->mutex);

    if (older != NULL) {
      SHIP_CONNECTION_STOP(older);
      ShipConnectionDelete(older);
    }

    if (sc != NULL) {
      SHIP_CONNECTION_STOP(sc);
      SHIP_NODE_READER_ON_REMOTE_SKI_DISCONNECTED(sn->ship_node_reader, SHIP_CONNECTION_GET_REMOTE_SKI(sc));
      ShipConnectionDelete(sc);
    }
  }
}

// Runs on the connection loop thread, which owns connection teardown. Each
// pending peer retains the certificate it presented, so only the peer named by
// the accepted request is promoted when several connections are active.
void ShipNodePromoteFingerprint(ShipNode* sn) {
  EEBUS_MUTEX_LOCK(sn->mutex);
  const size_t connection_count = NODE_CONNECTION_CONTAINER_GET_SIZE(sn->connections);
  EEBUS_MUTEX_UNLOCK(sn->mutex);
  for (size_t i = 0; i < connection_count; ++i) {
    EEBUS_MUTEX_LOCK(sn->mutex);
    NodeConnectionObject* nc         = NODE_CONNECTION_CONTAINER_GET_WITH_INDEX(sn->connections, i);
    NodeConnection* const connection = NODE_CONNECTION(nc);
    ShipConnectionObject* sc         = connection->connection;
    bool promote = ShipNodeShouldPromotePendingPeer(sc != NULL, connection->peer_fingerprint, sn->remote_fingerprint);
    if (promote) {
      char* const expected_fingerprint = StringCopy(sn->remote_fingerprint);
      promote                          = (expected_fingerprint != NULL);
      if (promote) {
        connection->is_trusted         = true;
        connection->provisional        = false;
        connection->trusted_by_pairing = true;
        StringDelete(connection->expected_fingerprint);
        connection->expected_fingerprint = expected_fingerprint;
      }
    }
    EEBUS_MUTEX_UNLOCK(sn->mutex);

    if (promote) {
      ShipConnectionApprovePendingHandshakeWithToken(sc, 0, ShipNodeAcceptPendingTrust, sn);
    }
  }
}

bool SkiMatches(const char* ski_a, const char* ski_b) {
  if (StringIsEmpty(ski_a) || StringIsEmpty(ski_b)) {
    return false;
  }

  return StringEqualsIgnoreCase(ski_a, ski_b);
}

static bool ShipNodeFindServiceForPeer(ShipNode* self, NodeConnectionObject* nc, MdnsEntry* found_entry) {
  if (self->cancel) {
    return false;
  }

  const size_t size = VectorGetSize(self->mdns_entries);
  if (size == 0) {
    return false;
  }

  for (size_t i = 0; i < size; i++) {
    MdnsEntry* entry    = (MdnsEntry*)VectorGetElement(self->mdns_entries, i);
    const char* ship_id = NODE_CONNECTION(nc)->ship_id;
    const bool matches  = !StringIsEmpty(ship_id) && !StringIsEmpty(NODE_CONNECTION(nc)->expected_fingerprint)
                              ? ((entry->id != NULL) && (strcmp(entry->id, ship_id) == 0))
                              : SkiMatches(entry->ski, NODE_CONNECTION_GET_SKI(nc));
    if (matches && !StringIsEmpty(entry->ski)) {
      *found_entry = *entry;
      return true;
    }
  }

  return false;
}

// Attempt a client connection for nc.  Must be called with mutex held;
// nc must be non-NULL with no attempt already running.
static void ShipNodeConnectToPendingSkiInternal(ShipNode* self, NodeConnectionObject* nc) {
  MdnsEntry found = {0};
  if (!ShipNodeFindServiceForPeer(self, nc, &found)) {
    return;
  }

  NodeConnection* peer = NODE_CONNECTION(nc);
  if (!SkiMatches(peer->ski, found.ski)) {
    // Discovery locates the endpoint. Its SKI is checked against the certificate
    // for bookkeeping; trust still depends on the configured fingerprint.
    NodeConnectionObject* existing = NODE_CONNECTION_CONTAINER_FIND_WITH_SKI(self->connections, found.ski);
    if ((existing != NULL) && (existing != nc)) {
      return;
    }

    char* ski_copy = StringCopy(found.ski);
    if (ski_copy == NULL) {
      return;
    }

    StringDelete((char*)peer->ski);
    peer->ski = ski_copy;
  }

  const char* const uri = MdnsEntryToUri(&found);

  WebsocketCreatorObject* wsc
      = WebsocketClientCreatorCreateWithFingerprint(uri, self->tsl_certificate, peer->ski, peer->expected_fingerprint);

  StringDelete((char*)uri);

  NODE_CONNECTION_CLIENT_CONNECT(nc, wsc, self->local_service_details->ship_id);
  WebsocketCreatorDelete(wsc);
}

static void ShipNodeConnectToPendingSki(ShipNode* self, const char* ski) {
  if (!ShipNodeIsClientSupported(self)) {
    return;
  }

  EEBUS_MUTEX_LOCK(self->mutex);
  NodeConnectionObject* nc = NODE_CONNECTION_CONTAINER_FIND_WITH_SKI(self->connections, ski);
  if ((nc != NULL) && !NODE_CONNECTION_IS_ATTEMPT_RUNNING(nc)) {
    ShipNodeConnectToPendingSkiInternal(self, nc);
  }

  EEBUS_MUTEX_UNLOCK(self->mutex);
}

static void ShipNodeConnectToAllPendingSkis(ShipNode* self) {
  if (!ShipNodeIsClientSupported(self)) {
    return;
  }

  EEBUS_MUTEX_LOCK(self->mutex);

  for (size_t i = 0; i < NODE_CONNECTION_CONTAINER_GET_SIZE(self->connections); ++i) {
    NodeConnectionObject* nc = NODE_CONNECTION_CONTAINER_GET_WITH_INDEX(self->connections, i);
    if (!NODE_CONNECTION_IS_ATTEMPT_RUNNING(nc)) {
      ShipNodeConnectToPendingSkiInternal(self, nc);
    }
  }

  self->search_for_remote_ski = false;
  EEBUS_MUTEX_UNLOCK(self->mutex);
}

static void ShipNodeApprovePendingHandshake(ShipNode* self, ShipConnectionObject* sc, uint64_t approval_id) {
  EEBUS_MUTEX_LOCK(self->mutex);
  NodeConnectionObject* obj = NODE_CONNECTION_CONTAINER_FIND_WITH_SHIP_CONNECTION(self->connections, sc);
  NodeConnection* nc        = (obj == NULL) ? NULL : NODE_CONNECTION(obj);
  const bool current        = NodeConnectionHasPendingApproval(nc, sc, approval_id);
  EEBUS_MUTEX_UNLOCK(self->mutex);

  if (current) {
    if (ShipConnectionApprovePendingHandshakeWithToken(sc, approval_id, ShipNodeAcceptPendingTrust, self)
        != kEebusErrorOk) {
      ShipNodeDiscardPendingTrust(self, sc, approval_id);
    }
  }
}

// SHIP 12.2.3: of two connections to one peer, the node with the bigger SKI
// keeps the newer one and closes the older at once. The node with the smaller
// SKI keeps both and leaves the choice to the peer, closing the older one
// itself only if the peer has not closed either within 3 seconds.
static void ShipNodeResolveDoubleConnection(ShipNode* self, const char* remote_ski, ShipConnectionObject* older) {
  if (ShipNodeHasBiggerSki(self->local_ski, remote_ski)) {
    ShipNodeQueueMessage queue_msg = {
        .type            = kShipNodeQueueMsgTypeCloseDoubleConnection,
        .ship_connection = older,
    };

    EEBUS_QUEUE_SEND(self->msg_queue, &queue_msg, kTimeoutInfinite);
  } else if (self->double_connection_timer != NULL) {
    EEBUS_TIMER_STOP(self->double_connection_timer);
    EEBUS_TIMER_START(self->double_connection_timer, kDoubleConnectionTimeoutMs, false);
  }
}

// Runs on the connection loop thread, the only one that deletes connections.
// A connection in data exchange is ended with an SME close announcement
// (13.4.8) giving no reason, as the peer stays trusted.
static void ShipNodeCloseDoubleConnection(ShipNode* self, ShipConnectionObject* sc) {
  EEBUS_MUTEX_LOCK(self->mutex);
  NodeConnectionObject* nc = NODE_CONNECTION_CONTAINER_FIND_WITH_SHIP_CONNECTION(self->connections, sc);
  const bool superseded    = (nc != NULL) && (NODE_CONNECTION(nc)->superseded == sc);
  EEBUS_MUTEX_UNLOCK(self->mutex);

  if (superseded) {
    SHIP_NODE_DEBUG_PRINTF("%s(), closing the older of two connections to a peer\n", __func__);
    SHIP_CONNECTION_CLOSE_CONNECTION(sc, true, 0, kShipCloseReasonUnspecific);
  }
}

// The peer with the bigger SKI left a double connection open for 3 seconds.
// The older connection is closed without the WebSocket ping probe of 12.2.3.
static void ShipNodeCloseAllDoubleConnections(ShipNode* self) {
  EEBUS_MUTEX_LOCK(self->mutex);
  const size_t connection_count = NODE_CONNECTION_CONTAINER_GET_SIZE(self->connections);
  EEBUS_MUTEX_UNLOCK(self->mutex);
  for (size_t i = 0; i < connection_count; ++i) {
    EEBUS_MUTEX_LOCK(self->mutex);
    NodeConnectionObject* nc = NODE_CONNECTION_CONTAINER_GET_WITH_INDEX(self->connections, i);
    ShipConnectionObject* sc = (nc == NULL) ? NULL : NODE_CONNECTION(nc)->superseded;
    EEBUS_MUTEX_UNLOCK(self->mutex);

    if (sc != NULL) {
      ShipNodeCloseDoubleConnection(self, sc);
    }
  }
}

void* ShipNodeConnectionLoop(void* ctx) {
  ShipNode* const sn             = (ShipNode*)ctx;
  ShipNodeQueueMessage queue_msg = {0};
  EebusError err                 = kEebusErrorOk;

  while (!sn->cancel) {
    err = EEBUS_QUEUE_RECEIVE(sn->msg_queue, &queue_msg, kTimeoutInfinite);
    if (err != kEebusErrorOk) {
      continue;
    }

    if (queue_msg.type == kShipNodeQueueMsgTypeMdnsEntriesFound) {
      ShipNodeConnectToAllPendingSkis(sn);
    } else if (queue_msg.type == kShipNodeQueueMsgTypeShipConnectionClosed) {
      CloseShipConnection(sn, queue_msg.ship_connection, queue_msg.had_error);
    } else if (queue_msg.type == kShipNodeQueueMsgTypeShipUnregisterSki) {
      ShipNodeUnregisterSki(SHIP_NODE_OBJECT(sn), queue_msg.ski);
    } else if (queue_msg.type == kShipNodeQueueMsgTypeShipRegisterSki) {
      ShipNodeRegisterSki(SHIP_NODE_OBJECT(sn), queue_msg.ski, queue_msg.is_trusted);
      ShipNodeConnectToPendingSki(sn, queue_msg.ski);
    } else if (queue_msg.type == kShipNodeQueueMsgTypeShipCancelPairingSki) {
      ShipNodeCancelPairingSki(SHIP_NODE_OBJECT(sn), queue_msg.ski);
    } else if (queue_msg.type == kShipNodeQueueMsgTypeRetryConnectionForSki) {
      ShipNodeConnectToPendingSki(sn, queue_msg.ski);
    } else if (queue_msg.type == kShipNodeQueueMsgTypePromoteFingerprint) {
      ShipNodePromoteFingerprint(sn);
    } else if (queue_msg.type == kShipNodeQueueMsgTypeApprovePendingSki) {
      ShipNodeApprovePendingHandshake(sn, queue_msg.ship_connection, queue_msg.approval_id);
    } else if (queue_msg.type == kShipNodeQueueMsgTypeRevokePairingFingerprint) {
      ShipNodeRevokePairingFingerprint(sn, queue_msg.ski);
    } else if (queue_msg.type == kShipNodeQueueMsgTypeCloseDoubleConnection) {
      ShipNodeCloseDoubleConnection(sn, queue_msg.ship_connection);
    } else if (queue_msg.type == kShipNodeQueueMsgTypeDoubleConnectionTimeout) {
      ShipNodeCloseAllDoubleConnections(sn);
    }

    ShipNodeQueueMsgDeallocator(&queue_msg);
  }

  return NULL;
}

// Caller holds the node mutex. An incoming connection that set the current one
// aside and then failed hands the current role back to it.
static void ShipNodeRejectDoubleConnection(NodeConnectionObject* nc, bool double_connection) {
  if (double_connection) {
    NODE_CONNECTION_RESTORE_SUPERSEDED_CONNECTION(nc);
  }
}

int ShipNodeOnWebsocketServerConnectionCallback(const char* ski, WebsocketCreatorObject* websocket_creator, void* ctx) {
  ShipNode* const sn = (ShipNode*)ctx;

  if (sn->cancel) {
    return -1;
  }

  // SKI check and connection decision share one lock — no state-change window between them.
  // Release before EEBUS_QUEUE_SEND (deadlock risk: websocket thread blocks on full queue
  // while the connection loop thread waits for the mutex to drain it).
  EEBUS_MUTEX_LOCK(sn->mutex);

  const char* const peer_fingerprint = HttpServerGetPeerFingerprint(sn->http_server);

  NodeConnectionObject* nc = NODE_CONNECTION_CONTAINER_FIND_WITH_SKI(sn->connections, ski);
  if (nc == NULL) {
    nc = NODE_CONNECTION_CONTAINER_FIND_WITH_FINGERPRINT(sn->connections, peer_fingerprint);
  }

  // The stored certificate fingerprint must match even when the SKI is already recognised.
  if ((nc != NULL) && !StringIsEmpty(NODE_CONNECTION(nc)->expected_fingerprint)
      && !ShipNodeFingerprintMatches(peer_fingerprint, NODE_CONNECTION(nc)->expected_fingerprint)) {
    EEBUS_MUTEX_UNLOCK(sn->mutex);
    return -1;
  }

  const bool was_trusted        = (nc != NULL) && NODE_CONNECTION(nc)->is_trusted;
  const char* const trusted_ski = was_trusted ? NODE_CONNECTION_GET_SKI(nc) : NULL;

  const bool recognised_by_current_pairing = ShipNodeFingerprintMatches(peer_fingerprint, sn->remote_fingerprint);

  const bool recognised_by_certificate
      = recognised_by_current_pairing
        || (was_trusted && ShipNodeFingerprintMatches(peer_fingerprint, NODE_CONNECTION(nc)->expected_fingerprint));

  const bool recognised = SkiMatches(ski, trusted_ski) || recognised_by_certificate;
  if ((nc == NULL) && !recognised && (sn->trust_mode != kEebusTrustModePostTrust)
      && !INFO_PROVIDER_IS_WAITING_FOR_TRUST_ALLOWED(sn, ski)) {
    EEBUS_MUTEX_UNLOCK(sn->mutex);
    SHIP_NODE_DEBUG_PRINTF("%s(), Remote SKI and certificate are not trusted\n", __func__);
    return -1;
  }

  // SHIP 12.2.3: a trusted peer may connect while another connection to it is
  // open. The incoming connection, whose TLS handshake has just completed, is
  // the newer one; the other is set aside until one of the two is closed.
  bool double_connection = false;
  if ((nc != NULL) && NODE_CONNECTION_IS_ATTEMPT_RUNNING(nc)) {
    if (!recognised || !NODE_CONNECTION_SUPERSEDE_CONNECTION(nc)) {
      EEBUS_MUTEX_UNLOCK(sn->mutex);
      SHIP_NODE_DEBUG_PRINTF("%s(), rejecting: already connected\n", __func__);
      return -1;
    }

    double_connection = true;
  }

  if (nc == NULL) {
    nc = NODE_CONNECTION_CONTAINER_GET_OR_CREATE(sn->connections, ski, sn, ShipNodeRetryTimerCallback);
    if (nc != NULL) {
      NODE_CONNECTION(nc)->is_trusted  = recognised || (sn->trust_mode != kEebusTrustModePostTrust);
      NODE_CONNECTION(nc)->provisional = !NODE_CONNECTION(nc)->is_trusted;
    }
  } else if (recognised) {
    NODE_CONNECTION(nc)->is_trusted  = true;
    NODE_CONNECTION(nc)->provisional = false;
  }

  if (nc == NULL) {
    EEBUS_MUTEX_UNLOCK(sn->mutex);
    return -1;
  }

  if (recognised_by_current_pairing) {
    char* const expected_fingerprint = StringCopy(sn->remote_fingerprint);
    if (expected_fingerprint == NULL) {
      NODE_CONNECTION(nc)->is_trusted  = false;
      NODE_CONNECTION(nc)->provisional = true;
      ShipNodeRejectDoubleConnection(nc, double_connection);
      EEBUS_MUTEX_UNLOCK(sn->mutex);
      return -1;
    }

    StringDelete(NODE_CONNECTION(nc)->expected_fingerprint);
    NODE_CONNECTION(nc)->expected_fingerprint = expected_fingerprint;
    NODE_CONNECTION(nc)->trusted_by_pairing   = true;
  }

  if (!SkiMatches(NODE_CONNECTION(nc)->ski, ski)) {
    char* ski_copy = StringCopy(ski);
    if (ski_copy == NULL) {
      ShipNodeRejectDoubleConnection(nc, double_connection);
      EEBUS_MUTEX_UNLOCK(sn->mutex);
      return -1;
    }

    StringDelete((char*)NODE_CONNECTION(nc)->ski);
    NODE_CONNECTION(nc)->ski = ski_copy;
  }

  StringDelete(NODE_CONNECTION(nc)->peer_fingerprint);
  NODE_CONNECTION(nc)->peer_fingerprint = StringCopy(peer_fingerprint);

  if (NODE_CONNECTION_SERVER_CONNECT(nc, websocket_creator, sn->local_service_details->ship_id) != kEebusErrorOk) {
    ShipNodeRejectDoubleConnection(nc, double_connection);
    EEBUS_MUTEX_UNLOCK(sn->mutex);
    SHIP_NODE_DEBUG_PRINTF("%s(), creating ship connection failed\n", __func__);
    return -1;
  }

  ShipConnectionObject* const older = double_connection ? NODE_CONNECTION(nc)->superseded : NULL;
  EEBUS_MUTEX_UNLOCK(sn->mutex);

  if (older != NULL) {
    ShipNodeResolveDoubleConnection(sn, ski, older);
  }

  return 0;
}

bool ShipNodeIsClientSupported(ShipNode* self) {
  return (self->role == kShipRoleClient) || (self->role == kShipRoleAuto);
}

bool ShipNodeIsServerSupported(ShipNode* self) {
  return (self->role == kShipRoleServer) || (self->role == kShipRoleAuto);
}

void Start(ShipNodeObject* self) {
  ShipNode* const sn = SHIP_NODE(self);

  if (ShipNodeIsServerSupported(sn)) {
    HTTP_SERVER_START(sn->http_server);
  }

  // Looking for shippairing requests only while one could be accepted. The
  // evaluator reports when that changes, but the secret may have been set
  // before the node was started, so the current answer is applied here too.
  if ((sn->ship_pairing != NULL) && SHIP_PAIRING_IS_ENABLED(sn->ship_pairing)) {
    SHIP_MDNS_START_PAIRING_BROWSE(sn->mdns, ShipNodeOnPairingEntriesFoundCallback, sn);
  }

  SHIP_MDNS_START(sn->mdns);

  sn->connection_thread = EebusThreadCreate(ShipNodeConnectionLoop, sn, 4 * 1024);
  if (sn->connection_thread == NULL) {
    SHIP_NODE_DEBUG_PRINTF("%s(), client connection thread creation failed\n", __func__);
  }
}

void Stop(ShipNodeObject* self) {
  ShipNode* const sn = SHIP_NODE(self);

  SHIP_NODE_DEBUG_PRINTF("ShipNode::%s(): begin\n", __func__);
  sn->cancel = true;

  if (sn->connection_thread != NULL) {
    ShipNodeQueueMessage queue_msg = {.type = kShipNodeQueueMsgTypeCancel, .ski = NULL};
    EEBUS_QUEUE_SEND(sn->msg_queue, &queue_msg, kTimeoutInfinite);
    EEBUS_THREAD_JOIN(sn->connection_thread);
    EebusThreadDelete(sn->connection_thread);
    sn->connection_thread = NULL;
  }

  // Stop all active connections so Destruct never encounters a live connection.
  // Iterate with mutex held but release before SHIP_CONNECTION_STOP (blocks on
  // thread join) to avoid a deadlock with the connection's own close callback.
  if (sn->double_connection_timer != NULL) {
    EEBUS_TIMER_STOP(sn->double_connection_timer);
  }

  for (size_t i = 0; i < NODE_CONNECTION_CONTAINER_GET_SIZE(sn->connections); ++i) {
    EEBUS_MUTEX_LOCK(sn->mutex);
    NodeConnectionObject* nc    = NODE_CONNECTION_CONTAINER_GET_WITH_INDEX(sn->connections, i);
    ShipConnectionObject* older = NODE_CONNECTION_RELEASE_SUPERSEDED_CONNECTION(nc);
    ShipConnectionObject* sc    = NODE_CONNECTION_RELEASE_SHIP_CONNECTION(nc);
    NODE_CONNECTION_STOP_RETRY_TIMER(nc);
    EEBUS_MUTEX_UNLOCK(sn->mutex);

    if (older != NULL) {
      SHIP_CONNECTION_STOP(older);
      ShipConnectionDelete(older);
    }

    if (sc != NULL) {
      SHIP_CONNECTION_STOP(sc);
      SHIP_NODE_READER_ON_REMOTE_SKI_DISCONNECTED(sn->ship_node_reader, SHIP_CONNECTION_GET_REMOTE_SKI(sc));
      ShipConnectionDelete(sc);
    }
  }

  SHIP_MDNS_STOP(sn->mdns);

  if (ShipNodeIsServerSupported(sn)) {
    HTTP_SERVER_STOP(sn->http_server);
  }

  SHIP_NODE_DEBUG_PRINTF("ShipNode::%s(): end\n", __func__);
}

void ShipNodeRegisterSki(ShipNodeObject* self, const char* ski, bool is_trusted) {
  ShipNode* const sn = SHIP_NODE(self);

  EEBUS_MUTEX_LOCK(sn->mutex);
  NodeConnectionObject* nc
      = NODE_CONNECTION_CONTAINER_GET_OR_CREATE(sn->connections, ski, sn, ShipNodeRetryTimerCallback);
  if (nc != NULL) {
    NODE_CONNECTION(nc)->is_trusted  = is_trusted;
    NODE_CONNECTION(nc)->provisional = false;

    NODE_CONNECTION(nc)->pending_approval_id = 0;
  }

  EEBUS_MUTEX_UNLOCK(sn->mutex);
}

void RegisterRemoteSki(ShipNodeObject* self, const char* ski, bool is_trusted) {
  ShipNode* const sn = SHIP_NODE(self);

  if (!is_trusted) {
    EEBUS_MUTEX_LOCK(sn->mutex);
    NodeConnectionObject* nc = NODE_CONNECTION_CONTAINER_FIND_WITH_SKI(sn->connections, ski);
    if (nc != NULL) {
      NODE_CONNECTION(nc)->pending_approval_id = 0;
    }

    EEBUS_MUTEX_UNLOCK(sn->mutex);
  }

  ShipNodeQueueMessage queue_msg = {
      .type            = kShipNodeQueueMsgTypeShipRegisterSki,
      .ship_connection = NULL,
      .had_error       = false,
      .is_trusted      = is_trusted,
      .ski             = StringCopy(ski),
  };

  EEBUS_QUEUE_SEND(sn->msg_queue, &queue_msg, kTimeoutInfinite);
}

void ShipNodeUnregisterSki(ShipNodeObject* self, const char* ski) {
  ShipNode* const sn = SHIP_NODE(self);

  EEBUS_MUTEX_LOCK(sn->mutex);
  NodeConnectionObject* nc    = NODE_CONNECTION_CONTAINER_FIND_WITH_SKI(sn->connections, ski);
  ShipConnectionObject* sc    = NULL;
  ShipConnectionObject* older = NULL;
  if (nc != NULL) {
    older = NODE_CONNECTION_RELEASE_SUPERSEDED_CONNECTION(nc);
    sc    = NODE_CONNECTION_RELEASE_SHIP_CONNECTION(nc);
    NODE_CONNECTION_CONTAINER_REMOVE_WITH_SKI(sn->connections, ski);
  }

  EEBUS_MUTEX_UNLOCK(sn->mutex);

  if (older != NULL) {
    SHIP_CONNECTION_STOP(older);
    ShipConnectionDelete(older);
  }

  if (sc != NULL) {
    SHIP_CONNECTION_STOP(sc);
    SHIP_NODE_READER_ON_REMOTE_SKI_DISCONNECTED(sn->ship_node_reader, SHIP_CONNECTION_GET_REMOTE_SKI(sc));
    ShipConnectionDelete(sc);
  }
}

void UnregisterRemoteSki(ShipNodeObject* self, const char* ski) {
  ShipNode* const sn = SHIP_NODE(self);

  EEBUS_MUTEX_LOCK(sn->mutex);
  NodeConnectionObject* nc = NODE_CONNECTION_CONTAINER_FIND_WITH_SKI(sn->connections, ski);
  const bool registered    = nc != NULL;
  if (nc != NULL) {
    NODE_CONNECTION(nc)->pending_approval_id = 0;
  }

  EEBUS_MUTEX_UNLOCK(sn->mutex);

  if (!registered) {
    SHIP_NODE_DEBUG_PRINTF("%s(), SKI not registered\n", __func__);
    return;
  }

  ShipNodeQueueMessage queue_msg = {
      .type            = kShipNodeQueueMsgTypeShipUnregisterSki,
      .ship_connection = NULL,
      .had_error       = false,
      .ski             = StringCopy(ski),
  };

  EEBUS_QUEUE_SEND(sn->msg_queue, &queue_msg, kTimeoutInfinite);
}

void ShipNodeCancelPairingSki(ShipNodeObject* self, const char* ski) {
  ShipNode* const sn = SHIP_NODE(self);

  if (StringIsEmpty(ski)) {
    return;
  }

  EEBUS_MUTEX_LOCK(sn->mutex);
  NodeConnectionObject* nc = NODE_CONNECTION_CONTAINER_FIND_WITH_SKI(sn->connections, ski);
  ShipConnectionObject* sc = (nc == NULL) ? NULL : NODE_CONNECTION(nc)->connection;
  const bool provisional   = (nc != NULL) && NODE_CONNECTION(nc)->provisional;
  if (nc != NULL) {
    NODE_CONNECTION(nc)->pending_approval_id = 0;
  }

  EEBUS_MUTEX_UNLOCK(sn->mutex);

  if (provisional && (sc != NULL)) {
    SHIP_CONNECTION_ABORT_PENDING_HANDSHAKE(sc);
  } else if (provisional) {
    EEBUS_MUTEX_LOCK(sn->mutex);
    NODE_CONNECTION_CONTAINER_REMOVE_WITH_SKI(sn->connections, ski);
    EEBUS_MUTEX_UNLOCK(sn->mutex);
  }
}

void ApprovePendingHandshakeWithSki(ShipNodeObject* self, const char* ski) {
  ShipNode* const sn             = SHIP_NODE(self);
  ShipNodeQueueMessage queue_msg = {.type = kShipNodeQueueMsgTypeApprovePendingSki};
  if (StringIsEmpty(ski)) {
    return;
  }

  EEBUS_MUTEX_LOCK(sn->mutex);
  NodeConnectionObject* obj = NODE_CONNECTION_CONTAINER_FIND_WITH_SKI(sn->connections, ski);
  NodeConnection* nc        = (obj == NULL) ? NULL : NODE_CONNECTION(obj);
  if (!sn->cancel && (nc != NULL) && (nc->connection != NULL) && (nc->pending_approval_id == 0)
      && (sn->next_approval_id != UINT64_MAX)) {
    queue_msg.ship_connection = nc->connection;
    queue_msg.approval_id = nc->pending_approval_id = ++sn->next_approval_id;
  }

  EEBUS_MUTEX_UNLOCK(sn->mutex);

  if (queue_msg.ship_connection == NULL) {
    return;
  }

  if (EEBUS_QUEUE_SEND(sn->msg_queue, &queue_msg, kTimeoutInfinite) != kEebusErrorOk) {
    ShipNodeDiscardPendingTrust(sn, queue_msg.ship_connection, queue_msg.approval_id);
  }
}

uint32_t GetPendingWaitingMsWithSki(ShipNodeObject* self, const char* ski) {
  ShipNode* const sn = SHIP_NODE(self);
  EEBUS_MUTEX_LOCK(sn->mutex);
  NodeConnectionObject* nc  = NODE_CONNECTION_CONTAINER_FIND_WITH_SKI(sn->connections, ski);
  ShipConnectionObject* sc  = (nc == NULL) ? NULL : NODE_CONNECTION(nc)->connection;
  const uint32_t waiting_ms = (sc == NULL) ? 0 : SHIP_CONNECTION_GET_PENDING_WAITING_MS(sc);
  EEBUS_MUTEX_UNLOCK(sn->mutex);
  return waiting_ms;
}

void CancelPairingWithSki(ShipNodeObject* self, const char* ski) {
  ShipNode* const sn = SHIP_NODE(self);

  if (StringIsEmpty(ski)) {
    return;
  }

  EEBUS_MUTEX_LOCK(sn->mutex);
  NodeConnectionObject* nc = NODE_CONNECTION_CONTAINER_FIND_WITH_SKI(sn->connections, ski);
  if (nc != NULL) {
    NODE_CONNECTION(nc)->pending_approval_id = 0;
  }

  EEBUS_MUTEX_UNLOCK(sn->mutex);

  ShipNodeQueueMessage queue_msg = {
      .type            = kShipNodeQueueMsgTypeShipCancelPairingSki,
      .ship_connection = NULL,
      .had_error       = false,
      .ski             = StringCopy(ski),
  };

  EEBUS_QUEUE_SEND(sn->msg_queue, &queue_msg, kTimeoutInfinite);
}
