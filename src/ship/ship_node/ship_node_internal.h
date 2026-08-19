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
#ifndef SRC_SHIP_SHIP_NODE_SHIP_NODE_INTERNAL_H_
#define SRC_SHIP_SHIP_NODE_SHIP_NODE_INTERNAL_H_

#include <stdbool.h>

#include "src/common/api/eebus_mutex_interface.h"
#include "src/common/api/eebus_queue_interface.h"
#include "src/common/api/eebus_thread_interface.h"
#include "src/common/service_details.h"
#include "src/common/string_util.h"
#include "src/ship/api/http_server_interface.h"
#include "src/ship/api/ship_connection_interface.h"
#include "src/ship/api/ship_mdns_interface.h"
#include "src/ship/api/ship_node_interface.h"
#include "src/ship/api/ship_node_reader_interface.h"
#include "src/ship/api/tls_certificate_interface.h"
#include "src/ship/api/websocket_creator_interface.h"
#include "src/ship/ship_connection/types.h"
#include "src/ship/ship_pairing/ship_pairing.h"

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

typedef struct ConnectionMapping ConnectionMapping;

struct ConnectionMapping {
  const char* ski;
  ShipConnectionInterface* connection;
  /** Which attempt is it to initate an connection to the remote SKI */
  int attempt_cnt;
  bool is_attempt_running;
  ServiceDetails* service_details;
};

typedef struct ShipNode ShipNode;

struct ShipNode {
  /** Implements the Ship Node Interface */
  ShipNodeObject sc_object;

  EebusQueueObject* msg_queue;
  char* remote_ski;
  ShipMdnsObject* mdns;
  Vector* mdns_entries;
  EebusMutexObject* mutex;
  bool search_for_remote_ski;
  bool cancel;
  EebusThreadObject* connection_thread;

  ConnectionMapping* connections_table;
  ShipNodeReaderObject* ship_node_reader;
  const TlsCertificateObject* tsl_certificate;
  ServiceDetails* local_service_details;
  // Temporary single SHIP Connection object instance
  // for early stage of Ship Node development and testing.
  // To be replaces with multiple instances handling
  ShipConnectionObject* ship_connection;
  WebsocketCreatorObject* websocket_creator;
  HttpServerObject* http_server;

  /**
   * @brief Certificate fingerprint the trusted node is expected to present
   *
   * Set when trust came from a shippairing request, which names a fingerprint
   * and not an SKI (SHIP Pairing Service TS 1.0.0, section 10.2). NULL when
   * trust came from a classic SHIP mechanism.
   */
  const char* remote_fingerprint;

  /** Evaluates the shippairing requests addressed to this node, chapter 9 */
  ShipPairingObject* ship_pairing;
  bool connection_attempt_running;
  ShipRole role;
};

#define SHIP_NODE(obj) ((ShipNode*)(obj))

/**
 * @brief Reports whether a connecting peer is the one this node trusts
 *
 * The whole of the decision, kept apart from the connection handling so that it
 * can be read and tested on its own. A peer is recognised by presenting the
 * trusted SKI, or by presenting the certificate whose fingerprint is trusted
 * (SHIP Pairing Service TS 1.0.0, section 10.2). The second is an additional
 * way to be recognised and never a way to bypass the first.
 *
 * @param peer_ski SKI derived from the certificate the peer presented
 * @param trusted_ski SKI this node trusts, or NULL if none
 * @param peer_fingerprint Fingerprint of the certificate the peer presented
 * @param trusted_fingerprint Fingerprint this node trusts, or NULL if none
 * @return true if the peer is recognised
 */
static inline bool ShipNodeIsPeerRecognised(
    const char* peer_ski,
    const char* trusted_ski,
    const char* peer_fingerprint,
    const char* trusted_fingerprint
) {
  if (!StringIsEmpty(peer_ski) && !StringIsEmpty(trusted_ski) && (strcmp(peer_ski, trusted_ski) == 0)) {
    return true;
  }

  // Section 10.2: a fingerprint that matches is to be treated exactly as a
  // trusted SKI is. It is an additional way to be recognised, never a way to
  // skip being recognised: with nothing registered to compare against, or
  // nothing presented to compare, no one is recognised here.
  if (StringIsEmpty(trusted_fingerprint) || StringIsEmpty(peer_fingerprint)) {
    return false;
  }

  return strcmp(peer_fingerprint, trusted_fingerprint) == 0;
}

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // SRC_SHIP_SHIP_NODE_SHIP_NODE_INTERNAL_H_
