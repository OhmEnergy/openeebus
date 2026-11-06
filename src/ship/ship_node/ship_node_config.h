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
 * @brief Ship Node connection policy
 *
 * SHIP 5.1 requires a node to retry cyclically when a connection to a trusted
 * peer does not complete, and leaves the interval to the product. A product
 * sets the values below as compile definitions, or in its generated EEBUS
 * configuration header (fw_fwk_eebus_configuration.h, FW_FWK_EEBUS_SHIP_*
 * names) when that header is on the include path; the defaults apply
 * otherwise.
 */

#ifndef SRC_SHIP_SHIP_NODE_SHIP_NODE_CONFIG_H_
#define SRC_SHIP_SHIP_NODE_SHIP_NODE_CONFIG_H_

#if defined(__has_include)
#if __has_include("fw_fwk_eebus_configuration.h")
#include "fw_fwk_eebus_configuration.h"
#endif
#endif

#if !defined(SHIP_NODE_RETRY_FIRST_DELAY_MS) && defined(FW_FWK_EEBUS_SHIP_RETRY_FIRST_DELAY_MS)
#define SHIP_NODE_RETRY_FIRST_DELAY_MS FW_FWK_EEBUS_SHIP_RETRY_FIRST_DELAY_MS
#endif

#if !defined(SHIP_NODE_RETRY_INITIAL_DELAY_MS) && defined(FW_FWK_EEBUS_SHIP_RETRY_INITIAL_DELAY_MS)
#define SHIP_NODE_RETRY_INITIAL_DELAY_MS FW_FWK_EEBUS_SHIP_RETRY_INITIAL_DELAY_MS
#endif

#if !defined(SHIP_NODE_RETRY_DELAY_FACTOR) && defined(FW_FWK_EEBUS_SHIP_RETRY_DELAY_FACTOR)
#define SHIP_NODE_RETRY_DELAY_FACTOR FW_FWK_EEBUS_SHIP_RETRY_DELAY_FACTOR
#endif

#if !defined(SHIP_NODE_RETRY_MAX_DELAY_MS) && defined(FW_FWK_EEBUS_SHIP_RETRY_MAX_DELAY_MS)
#define SHIP_NODE_RETRY_MAX_DELAY_MS FW_FWK_EEBUS_SHIP_RETRY_MAX_DELAY_MS
#endif

#if !defined(SHIP_NODE_DIAL_MIN_INTERVAL_MS) && defined(FW_FWK_EEBUS_SHIP_DIAL_MIN_INTERVAL_MS)
#define SHIP_NODE_DIAL_MIN_INTERVAL_MS FW_FWK_EEBUS_SHIP_DIAL_MIN_INTERVAL_MS
#endif

/**
 * @brief Delay before the first retry after a connection to a peer closes
 */
#ifndef SHIP_NODE_RETRY_FIRST_DELAY_MS
#define SHIP_NODE_RETRY_FIRST_DELAY_MS 0
#endif

/**
 * @brief Delay before the second retry
 */
#ifndef SHIP_NODE_RETRY_INITIAL_DELAY_MS
#define SHIP_NODE_RETRY_INITIAL_DELAY_MS 3000
#endif

/**
 * @brief Factor applied to the previous delay for each later retry
 *
 * The result never exceeds SHIP_NODE_RETRY_MAX_DELAY_MS. With the default
 * values the third and every later retry waits the maximum delay.
 */
#ifndef SHIP_NODE_RETRY_DELAY_FACTOR
#define SHIP_NODE_RETRY_DELAY_FACTOR 4
#endif

/**
 * @brief Upper bound of the delay between two retries
 */
#ifndef SHIP_NODE_RETRY_MAX_DELAY_MS
#define SHIP_NODE_RETRY_MAX_DELAY_MS 10000
#endif

/**
 * @brief Shortest interval between the start of two outgoing connections
 *
 * Applies across all peers, on top of the rule that a dial starts only once
 * the previous one has been answered by its peer or has failed. A dial
 * requested sooner waits for the interval to end, so a peer that closes every
 * connection soon after accepting it cannot keep the node in back-to-back TLS
 * handshakes. Zero leaves only the one-dial-at-a-time rule.
 */
#ifndef SHIP_NODE_DIAL_MIN_INTERVAL_MS
#define SHIP_NODE_DIAL_MIN_INTERVAL_MS 1000
#endif

#endif  // SRC_SHIP_SHIP_NODE_SHIP_NODE_CONFIG_H_
