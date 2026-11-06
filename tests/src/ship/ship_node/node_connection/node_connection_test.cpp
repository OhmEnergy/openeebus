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
#include "src/ship/ship_node/node_connection.h"

#include <gtest/gtest.h>

#include "src/ship/ship_connection/ship_connection.h"
#include "src/ship/ship_node/node_connection_internal.h"
#include "src/ship/ship_node/ship_node_config.h"
#include "tests/src/memory_leak.inc"
#include "tests/src/mocks/common/eebus_timer/eebus_timer_mock.h"
#include "tests/src/mocks/ship/ship_connection/ship_connection_mock.h"

static ShipConnectionMock* ship_connection_mock = nullptr;

ShipConnectionObject* ShipConnectionCreate(InfoProviderObject*, ShipRole, const char*, const char*, const char*) {
  ship_connection_mock = ShipConnectionMockCreate();
  return SHIP_CONNECTION_OBJECT(ship_connection_mock);
}

static void NoOpRetryFn(void*) {}

class NodeConnectionTest : public ::testing::Test {
 protected:
  void SetUp() override {
    nc_ = NodeConnectionCreate("test_ski", nullptr, NoOpRetryFn);
    ASSERT_NE(nc_, nullptr);
  }

  void TearDown() override {
    NodeConnectionDelete(nc_);
    EXPECT_EQ(heap_used, 0);
    CheckForMemoryLeaks();
  }

  NodeConnectionObject* nc_ = nullptr;
};

TEST_F(NodeConnectionTest, GetSki) {
  EXPECT_STREQ(NODE_CONNECTION_GET_SKI(nc_), "test_ski");
}

TEST_F(NodeConnectionTest, IsAttemptRunningInitiallyFalse) {
  EXPECT_FALSE(NODE_CONNECTION_IS_ATTEMPT_RUNNING(nc_));
}

TEST_F(NodeConnectionTest, HandshakeCompleteIdempotent) {
  EXPECT_TRUE(NODE_CONNECTION_ON_HANDSHAKE_COMPLETE(nc_));
  EXPECT_FALSE(NODE_CONNECTION_ON_HANDSHAKE_COMPLETE(nc_));
}

TEST_F(NodeConnectionTest, HandshakeCompleteResetsAttemptCnt) {
  NODE_CONNECTION_ON_CONNECTION_CLOSED(nc_);
  NODE_CONNECTION_ON_CONNECTION_CLOSED(nc_);
  NODE_CONNECTION_ON_HANDSHAKE_COMPLETE(nc_);
  EXPECT_EQ(NODE_CONNECTION_ON_CONNECTION_CLOSED(nc_), 0u);
}

TEST_F(NodeConnectionTest, OnConnectionClosedIncrements) {
  EXPECT_EQ(NODE_CONNECTION_ON_CONNECTION_CLOSED(nc_), 0u);
  EXPECT_EQ(NODE_CONNECTION_ON_CONNECTION_CLOSED(nc_), 3000u);
  EXPECT_FALSE(NODE_CONNECTION_IS_ATTEMPT_RUNNING(nc_));
}

TEST_F(NodeConnectionTest, RetryDelayFollowsTheConfiguredSchedule) {
  EXPECT_EQ(NODE_CONNECTION_ON_CONNECTION_CLOSED(nc_), (uint32_t)SHIP_NODE_RETRY_FIRST_DELAY_MS);
  EXPECT_EQ(NODE_CONNECTION_ON_CONNECTION_CLOSED(nc_), (uint32_t)SHIP_NODE_RETRY_INITIAL_DELAY_MS);

  uint32_t previous = SHIP_NODE_RETRY_INITIAL_DELAY_MS;
  for (int i = 0; i < 20; ++i) {
    const uint32_t delay = NODE_CONNECTION_ON_CONNECTION_CLOSED(nc_);
    EXPECT_GE(delay, previous);
    EXPECT_LE(delay, (uint32_t)SHIP_NODE_RETRY_MAX_DELAY_MS);
    previous = delay;
  }

  EXPECT_EQ(previous, (uint32_t)SHIP_NODE_RETRY_MAX_DELAY_MS);
}

TEST_F(NodeConnectionTest, DefaultRetryDelaysAreZeroThenThreeThenTenSeconds) {
  EXPECT_EQ(NODE_CONNECTION_ON_CONNECTION_CLOSED(nc_), 0u);
  EXPECT_EQ(NODE_CONNECTION_ON_CONNECTION_CLOSED(nc_), 3000u);
  EXPECT_EQ(NODE_CONNECTION_ON_CONNECTION_CLOSED(nc_), 10000u);
  EXPECT_EQ(NODE_CONNECTION_ON_CONNECTION_CLOSED(nc_), 10000u);
}

TEST_F(NodeConnectionTest, ReleasedApprovalCannotAuthorizeAReplacementAtTheSameAddress) {
  NodeConnection* peer = NODE_CONNECTION(nc_);
  ShipConnectionObject connection{};
  peer->connection          = &connection;
  peer->pending_approval_id = 7;
  EXPECT_TRUE(NodeConnectionHasPendingApproval(peer, &connection, 7));

  EXPECT_EQ(NODE_CONNECTION_RELEASE_SHIP_CONNECTION(nc_), &connection);
  EXPECT_EQ(peer->pending_approval_id, 0u);
  // Model allocator address reuse: a replacement has a new approval token.
  peer->connection          = &connection;
  peer->pending_approval_id = 8;
  EXPECT_FALSE(NodeConnectionHasPendingApproval(peer, &connection, 7));
  EXPECT_TRUE(NodeConnectionHasPendingApproval(peer, &connection, 8));
  NODE_CONNECTION_RELEASE_SHIP_CONNECTION(nc_);
}

TEST_F(NodeConnectionTest, ClosingUnapprovedConnectionClearsItsTokenWithoutGrantingTrust) {
  NodeConnection* peer = NODE_CONNECTION(nc_);
  ShipConnectionObject connection{};
  peer->connection          = &connection;
  peer->pending_approval_id = 7;
  peer->provisional         = true;

  NODE_CONNECTION_ON_CONNECTION_CLOSED(nc_);

  EXPECT_EQ(peer->pending_approval_id, 0u);
  EXPECT_FALSE(NodeConnectionHasPendingApproval(peer, &connection, 7));
  EXPECT_FALSE(peer->is_trusted);
  EXPECT_TRUE(peer->provisional);
}

TEST_F(NodeConnectionTest, OwnsConnection) {
  ship_connection_mock = nullptr;
  NODE_CONNECTION_SERVER_CONNECT(nc_, nullptr, "ship_id");
  ShipConnectionMockGuard sc_guard{ship_connection_mock};
  ShipConnectionObject* sc = SHIP_CONNECTION_OBJECT(ship_connection_mock);
  ASSERT_NE(sc, nullptr);

  EXPECT_TRUE(NODE_CONNECTION_OWNS_CONNECTION(nc_, sc));

  ShipConnectionObject dummy{};
  EXPECT_FALSE(NODE_CONNECTION_OWNS_CONNECTION(nc_, &dummy));

  ShipConnectionObject* released = NODE_CONNECTION_RELEASE_SHIP_CONNECTION(nc_);
  EXPECT_EQ(released, SHIP_CONNECTION_OBJECT(ship_connection_mock));
}

TEST_F(NodeConnectionTest, ReleaseShipConnection) {
  ship_connection_mock = nullptr;
  NODE_CONNECTION_SERVER_CONNECT(nc_, nullptr, "ship_id");
  ShipConnectionMockGuard sc_guard{ship_connection_mock};
  ShipConnectionObject* sc = SHIP_CONNECTION_OBJECT(ship_connection_mock);
  ASSERT_NE(sc, nullptr);

  ShipConnectionObject* released = NODE_CONNECTION_RELEASE_SHIP_CONNECTION(nc_);
  EXPECT_EQ(released, sc);
  EXPECT_EQ(released, SHIP_CONNECTION_OBJECT(ship_connection_mock));
  EXPECT_FALSE(NODE_CONNECTION_OWNS_CONNECTION(nc_, sc));
}

TEST_F(NodeConnectionTest, ClientConnectBusyGuard) {
  ship_connection_mock = nullptr;
  NODE_CONNECTION_SERVER_CONNECT(nc_, nullptr, "ship_id");
  ShipConnectionMockGuard sc_guard{ship_connection_mock};

  EXPECT_TRUE(NODE_CONNECTION_IS_ATTEMPT_RUNNING(nc_));

  WebsocketCreatorObject dummy_wsc{nullptr};
  EXPECT_EQ(NODE_CONNECTION_CLIENT_CONNECT(nc_, &dummy_wsc, "ship_id"), kEebusErrorCommunicationBusy);

  ShipConnectionObject* released = NODE_CONNECTION_RELEASE_SHIP_CONNECTION(nc_);
  EXPECT_EQ(released, SHIP_CONNECTION_OBJECT(ship_connection_mock));
}

TEST_F(NodeConnectionTest, SupersedeSetsTheCurrentConnectionAside) {
  NodeConnection* peer = NODE_CONNECTION(nc_);
  ShipConnectionObject older{};
  peer->connection          = &older;
  peer->is_attempt_running  = true;
  peer->handshake_complete  = true;
  peer->pending_approval_id = 7;

  EXPECT_TRUE(NODE_CONNECTION_SUPERSEDE_CONNECTION(nc_));
  EXPECT_EQ(peer->connection, nullptr);
  EXPECT_EQ(peer->superseded, &older);
  EXPECT_TRUE(peer->superseded_handshake_complete);
  EXPECT_FALSE(peer->handshake_complete);
  EXPECT_FALSE(NODE_CONNECTION_IS_ATTEMPT_RUNNING(nc_));
  EXPECT_EQ(peer->pending_approval_id, 0u);
  EXPECT_TRUE(NODE_CONNECTION_OWNS_CONNECTION(nc_, &older));

  EXPECT_EQ(NODE_CONNECTION_RELEASE_SUPERSEDED_CONNECTION(nc_), &older);
  EXPECT_FALSE(NODE_CONNECTION_OWNS_CONNECTION(nc_, &older));
}

TEST_F(NodeConnectionTest, OnlyOneConnectionIsSetAside) {
  NodeConnection* peer = NODE_CONNECTION(nc_);
  ShipConnectionObject older{};
  ShipConnectionObject newer{};
  peer->connection = &older;
  ASSERT_TRUE(NODE_CONNECTION_SUPERSEDE_CONNECTION(nc_));
  peer->connection = &newer;

  EXPECT_FALSE(NODE_CONNECTION_SUPERSEDE_CONNECTION(nc_));
  EXPECT_EQ(peer->connection, &newer);
  EXPECT_EQ(peer->superseded, &older);

  NODE_CONNECTION_RELEASE_SUPERSEDED_CONNECTION(nc_);
  NODE_CONNECTION_RELEASE_SHIP_CONNECTION(nc_);
}

TEST_F(NodeConnectionTest, NothingIsSetAsideWithoutAConnection) {
  EXPECT_FALSE(NODE_CONNECTION_SUPERSEDE_CONNECTION(nc_));
  EXPECT_EQ(NODE_CONNECTION(nc_)->superseded, nullptr);
}

TEST_F(NodeConnectionTest, RestoreHandsTheCurrentRoleBack) {
  NodeConnection* peer = NODE_CONNECTION(nc_);
  ShipConnectionObject older{};
  peer->connection         = &older;
  peer->handshake_complete = true;
  ASSERT_TRUE(NODE_CONNECTION_SUPERSEDE_CONNECTION(nc_));

  NODE_CONNECTION_RESTORE_SUPERSEDED_CONNECTION(nc_);
  EXPECT_EQ(peer->connection, &older);
  EXPECT_EQ(peer->superseded, nullptr);
  EXPECT_TRUE(peer->handshake_complete);
  EXPECT_TRUE(NODE_CONNECTION_IS_ATTEMPT_RUNNING(nc_));

  NODE_CONNECTION_RELEASE_SHIP_CONNECTION(nc_);
}

TEST_F(NodeConnectionTest, SwapExchangesTheTwoConnections) {
  NodeConnection* peer = NODE_CONNECTION(nc_);
  ShipConnectionObject older{};
  ShipConnectionObject newer{};
  peer->connection         = &older;
  peer->handshake_complete = true;
  ASSERT_TRUE(NODE_CONNECTION_SUPERSEDE_CONNECTION(nc_));
  peer->connection = &newer;

  NODE_CONNECTION_SWAP_SUPERSEDED_CONNECTION(nc_);
  EXPECT_EQ(peer->connection, &older);
  EXPECT_TRUE(peer->handshake_complete);
  EXPECT_EQ(peer->superseded, &newer);
  EXPECT_FALSE(peer->superseded_handshake_complete);

  NODE_CONNECTION_RELEASE_SUPERSEDED_CONNECTION(nc_);
  NODE_CONNECTION_RELEASE_SHIP_CONNECTION(nc_);
}

TEST_F(NodeConnectionTest, OwnsNoNullConnection) {
  EXPECT_FALSE(NODE_CONNECTION_OWNS_CONNECTION(nc_, nullptr));
}

TEST_F(NodeConnectionTest, ClosingTheDialledConnectionEndsTheDial) {
  NodeConnection* peer = NODE_CONNECTION(nc_);
  ShipConnectionObject dialled{};
  peer->connection        = &dialled;
  peer->dialed_connection = &dialled;
  peer->dial_in_flight    = true;

  NODE_CONNECTION_ON_CONNECTION_CLOSED(nc_);
  EXPECT_EQ(peer->dialed_connection, nullptr);
  EXPECT_FALSE(peer->dial_in_flight);
}

TEST_F(NodeConnectionTest, ADialSetAsideIsStillInFlight) {
  NodeConnection* peer = NODE_CONNECTION(nc_);
  ShipConnectionObject dialled{};
  ShipConnectionObject incoming{};
  peer->connection        = &dialled;
  peer->dialed_connection = &dialled;
  peer->dial_in_flight    = true;

  ASSERT_TRUE(NODE_CONNECTION_SUPERSEDE_CONNECTION(nc_));
  peer->connection = &incoming;
  EXPECT_TRUE(peer->dial_in_flight);

  EXPECT_EQ(NODE_CONNECTION_RELEASE_SUPERSEDED_CONNECTION(nc_), &dialled);
  EXPECT_EQ(peer->dialed_connection, nullptr);
  EXPECT_FALSE(peer->dial_in_flight);

  NODE_CONNECTION_RELEASE_SHIP_CONNECTION(nc_);
}

TEST_F(NodeConnectionTest, ReleasingAnotherConnectionKeepsTheDial) {
  NodeConnection* peer = NODE_CONNECTION(nc_);
  ShipConnectionObject dialled{};
  ShipConnectionObject incoming{};
  peer->connection        = &dialled;
  peer->dialed_connection = &dialled;
  peer->dial_in_flight    = true;
  ASSERT_TRUE(NODE_CONNECTION_SUPERSEDE_CONNECTION(nc_));
  peer->connection = &incoming;

  EXPECT_EQ(NODE_CONNECTION_RELEASE_SHIP_CONNECTION(nc_), &incoming);
  EXPECT_EQ(peer->dialed_connection, &dialled);
  EXPECT_TRUE(peer->dial_in_flight);

  NODE_CONNECTION_RELEASE_SUPERSEDED_CONNECTION(nc_);
}

TEST_F(NodeConnectionTest, ADialSetAsideIsPendingUntilAnswered) {
  NodeConnection* peer = NODE_CONNECTION(nc_);
  ShipConnectionObject dialled{};
  ShipConnectionObject incoming{};
  peer->connection        = &dialled;
  peer->dialed_connection = &dialled;
  peer->dial_in_flight    = true;
  EXPECT_FALSE(NodeConnectionIsSupersededDialPending(peer));

  ASSERT_TRUE(NODE_CONNECTION_SUPERSEDE_CONNECTION(nc_));
  peer->connection = &incoming;
  EXPECT_TRUE(NodeConnectionIsSupersededDialPending(peer));

  peer->dial_in_flight = false;
  EXPECT_FALSE(NodeConnectionIsSupersededDialPending(peer));

  NODE_CONNECTION_RELEASE_SUPERSEDED_CONNECTION(nc_);
  NODE_CONNECTION_RELEASE_SHIP_CONNECTION(nc_);
}

TEST_F(NodeConnectionTest, AnIncomingConnectionSetAsideIsNoPendingDial) {
  NodeConnection* peer = NODE_CONNECTION(nc_);
  ShipConnectionObject incoming{};
  ShipConnectionObject dialled{};
  peer->connection = &incoming;
  ASSERT_TRUE(NODE_CONNECTION_SUPERSEDE_CONNECTION(nc_));
  peer->connection        = &dialled;
  peer->dialed_connection = &dialled;
  peer->dial_in_flight    = true;

  EXPECT_FALSE(NodeConnectionIsSupersededDialPending(peer));
  EXPECT_FALSE(NodeConnectionIsSupersededDialPending(nullptr));

  NODE_CONNECTION_RELEASE_SUPERSEDED_CONNECTION(nc_);
  NODE_CONNECTION_RELEASE_SHIP_CONNECTION(nc_);
}

TEST_F(NodeConnectionTest, SwappingAnAnsweredDialMakesItCurrent) {
  NodeConnection* peer = NODE_CONNECTION(nc_);
  ShipConnectionObject dialled{};
  ShipConnectionObject incoming{};
  peer->connection        = &dialled;
  peer->dialed_connection = &dialled;
  peer->dial_in_flight    = true;
  ASSERT_TRUE(NODE_CONNECTION_SUPERSEDE_CONNECTION(nc_));
  peer->connection         = &incoming;
  peer->handshake_complete = true;

  peer->dial_in_flight = false;
  NODE_CONNECTION_SWAP_SUPERSEDED_CONNECTION(nc_);
  EXPECT_EQ(peer->connection, &dialled);
  EXPECT_FALSE(peer->handshake_complete);
  EXPECT_EQ(peer->superseded, &incoming);
  EXPECT_TRUE(peer->superseded_handshake_complete);

  NODE_CONNECTION_RELEASE_SUPERSEDED_CONNECTION(nc_);
  NODE_CONNECTION_RELEASE_SHIP_CONNECTION(nc_);
}

TEST(NodeConnectionTimerTest, DeleteWithArmedTimerNoCrash) {
  NodeConnectionObject* nc = NodeConnectionCreate("ski", nullptr, NoOpRetryFn);
  ASSERT_NE(nc, nullptr);

  NODE_CONNECTION_SCHEDULE_RETRY(nc, 3000);

  EXPECT_NO_FATAL_FAILURE(NodeConnectionDelete(nc));
  EXPECT_EQ(heap_used, 0);
  CheckForMemoryLeaks();
}
