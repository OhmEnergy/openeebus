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
 * @file ship_pairing_test_suite.h
 * @brief shippairing test suite
 *
 * The fixtures are the worked example of the SHIP Pairing Service TS 1.0.0,
 * Annex A. Using the specification's own values means these tests fail if an
 * implementation is self-consistent but does not interoperate.
 */
#ifndef TESTS_SRC_SHIP_SHIP_PAIRING_SHIP_PAIRING_TEST_SUITE_H
#define TESTS_SRC_SHIP_SHIP_PAIRING_SHIP_PAIRING_TEST_SUITE_H

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

extern "C" {
#include "src/ship/api/ship_pairing_entry.h"
}

/** @brief SHIP ID of devA, Annex A.1 */
#define TEST_FOR_ID "i:983327_u:C8277H008F-3"
/** @brief SHA-256 fingerprint of the devA certificate, Annex A.1 */
#define TEST_FOR_PAR "C74B7855D3479415F62CC01E5F6D9A93EBC676057D85417ADA16FD1384338943"
/** @brief SHIP ID of devZ, Annex A.2 */
#define TEST_TRUST_ID "i:46925_u:43652bk-2-gt1"
/** @brief SHA-256 fingerprint of the devZ certificate, Annex A.2 */
#define TEST_TRUST_PAR "2CC72E781F7A7D2A08D50196C50FEDF0F7BA583F43F76C8C0DDEC9EEF0D005B4"
/** @brief devZ-nonce, Annex A.2 */
#define TEST_TRUST_NONCE "BDCEE427FA7208DF3C1F2A749BA6F4D4"
/** @brief Digest of the request, Annex A.3 */
#define TEST_DIGEST "BCBB62B2176DA2CEE545784CEB1F2A55E049451B12A549C98E8CA213F001DA25"
/** @brief devA-secret, Annex A.1 */
#define TEST_SECRET "7A37DCF81BDB50F8E92CFA4160CCB3DE"

#define TEST_INSTANCE_NAME "Control Unit ExampleCompany C8277H008F#1"
#define TEST_DOMAIN "local."

/** @brief One key-value pair of a TXT record */
using TxtPair = std::pair<std::string, std::string>;

class ShipPairingTestSuite : public testing::Test {
 public:
  using EntryPtr = std::unique_ptr<ShipPairingEntry, decltype(&ShipPairingEntryDelete)>;

  void TearDown() override;

  /**
   * @brief The eleven key-value pairs of the Annex A request, in specified order
   */
  static std::vector<TxtPair> AnnexAPairs();

  /**
   * @brief Encodes key-value pairs into the DNS-SD wire form of a TXT record
   *
   * Each pair becomes "key=value" preceded by one octet holding its length.
   */
  static std::string EncodeTxtRecord(const std::vector<TxtPair>& pairs);

  /**
   * @brief Creates an entry and parses a TXT record built from @p pairs into it
   */
  static EntryPtr ParseEntry(const std::vector<TxtPair>& pairs);

  /**
   * @brief Creates an entry holding the unmodified Annex A request
   */
  static EntryPtr AnnexAEntry();
};

#endif  // TESTS_SRC_SHIP_SHIP_PAIRING_SHIP_PAIRING_TEST_SUITE_H
