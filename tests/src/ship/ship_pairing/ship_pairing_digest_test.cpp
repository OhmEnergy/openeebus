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
 * @brief Tests for the shippairing digest, chapter 7
 */
#include "tests/src/ship/ship_pairing/ship_pairing_test_suite.h"

extern "C" {
#include "src/common/string_util.h"
#include "src/ship/ship_pairing/ship_pairing_digest.h"
}

namespace {

/** @brief Owns a string returned by the functions under test */
class OwnedString {
 public:
  explicit OwnedString(char* s) : s_(s) {}
  ~OwnedString() {
    StringDelete(s_);
  }

  OwnedString(const OwnedString&)            = delete;
  OwnedString& operator=(const OwnedString&) = delete;

  const char* Get() const {
    return s_;
  }

 private:
  char* s_;
};

/** @brief The devA-secret of Annex A.1 as octets */
std::vector<uint8_t> AnnexASecret() {
  std::vector<uint8_t> secret(SHIP_PAIRING_SECRET_SIZE);
  EXPECT_TRUE(StringHexToBytes(TEST_SECRET, secret.data(), secret.size()));
  return secret;
}

}  // namespace

TEST_F(ShipPairingTestSuite, BuildsTheSpecifiedMessage) {
  const EntryPtr entry = AnnexAEntry();
  ASSERT_NE(entry, nullptr);

  const OwnedString message(ShipPairingBuildMessage(entry.get()));
  ASSERT_NE(message.Get(), nullptr);

  // Annex A.3. The digest key is not part of the message, and the trailing
  // semicolon after the last pair is.
  EXPECT_STREQ(
      message.Get(),
      "txtvers=1;"
      "parType=fpSha256;"
      "forId=" TEST_FOR_ID
      ";"
      "forPar=" TEST_FOR_PAR
      ";"
      "trustId=" TEST_TRUST_ID
      ";"
      "trustPar=" TEST_TRUST_PAR
      ";"
      "trustCurve=secp256r1;"
      "type=addCu;"
      "trustNonce=" TEST_TRUST_NONCE
      ";"
      "alg=hmacSha256;"
  );
}

TEST_F(ShipPairingTestSuite, ReproducesTheSpecifiedDigest) {
  const EntryPtr entry              = AnnexAEntry();
  const std::vector<uint8_t> secret = AnnexASecret();
  ASSERT_NE(entry, nullptr);

  const OwnedString digest(ShipPairingCalcDigest(entry.get(), secret.data(), secret.size()));
  ASSERT_NE(digest.Get(), nullptr);

  EXPECT_STREQ(digest.Get(), TEST_DIGEST);
}

TEST_F(ShipPairingTestSuite, VerifiesTheSpecifiedRequest) {
  const EntryPtr entry              = AnnexAEntry();
  const std::vector<uint8_t> secret = AnnexASecret();
  ASSERT_NE(entry, nullptr);

  EXPECT_TRUE(ShipPairingVerifyDigest(entry.get(), secret.data(), secret.size()));
}

TEST_F(ShipPairingTestSuite, RejectsARequestAuthenticatedWithAnotherSecret) {
  const EntryPtr entry = AnnexAEntry();
  ASSERT_NE(entry, nullptr);

  std::vector<uint8_t> secret = AnnexASecret();
  secret[0] ^= 0x01;

  EXPECT_FALSE(ShipPairingVerifyDigest(entry.get(), secret.data(), secret.size()));
}

TEST_F(ShipPairingTestSuite, RejectsARequestWhoseDigestDoesNotCoverItsKeys) {
  // Every key of the message is covered by the digest, so altering any of them
  // has to invalidate the request. trustId is the one that matters most: it
  // names the node that would be trusted.
  const std::vector<std::string> keys = {
      "txtvers",
      "parType",
      "forId",
      "forPar",
      "trustId",
      "trustPar",
      "trustCurve",
      "type",
      "trustNonce",
  };

  const std::vector<uint8_t> secret = AnnexASecret();

  for (const auto& key : keys) {
    std::vector<TxtPair> pairs = AnnexAPairs();
    for (auto& pair : pairs) {
      if (pair.first != key) {
        continue;
      }

      // Keep every value within its permitted form, so that what the digest
      // rejects is the substitution rather than a malformed record.
      if (key == "trustCurve") {
        pair.second = "brainpoolP256r1";
      } else if (key == "type" || key == "parType" || key == "txtvers") {
        pair.second += "X";
      } else if (pair.second.back() == 'A') {
        pair.second.back() = 'B';
      } else {
        pair.second.back() = 'A';
      }
    }

    const EntryPtr entry = ParseEntry(pairs);
    ASSERT_NE(entry, nullptr) << "altered key: " << key;
    EXPECT_FALSE(ShipPairingVerifyDigest(entry.get(), secret.data(), secret.size())) << "altered key: " << key;
  }
}

TEST_F(ShipPairingTestSuite, RejectsARequestNamingAnUnsupportedAlgorithm) {
  std::vector<TxtPair> pairs = AnnexAPairs();
  for (auto& pair : pairs) {
    if (pair.first == "alg") {
      pair.second = "hmacSha512";
    }
  }

  const EntryPtr entry              = ParseEntry(pairs);
  const std::vector<uint8_t> secret = AnnexASecret();
  ASSERT_NE(entry, nullptr);

  // The algorithm is not guessed at: an unknown one cannot be authenticated.
  EXPECT_EQ(ShipPairingCalcDigest(entry.get(), secret.data(), secret.size()), nullptr);
  EXPECT_FALSE(ShipPairingVerifyDigest(entry.get(), secret.data(), secret.size()));
}

TEST_F(ShipPairingTestSuite, RefusesToBuildAMessageFromAnIncompleteRecord) {
  std::vector<TxtPair> pairs = AnnexAPairs();
  pairs.erase(pairs.begin() + 4);  // trustId

  const EntryPtr entry = ParseEntry(pairs);
  ASSERT_NE(entry, nullptr);

  EXPECT_EQ(ShipPairingBuildMessage(entry.get()), nullptr);
}

TEST_F(ShipPairingTestSuite, RejectsInvalidArguments) {
  const EntryPtr entry              = AnnexAEntry();
  const std::vector<uint8_t> secret = AnnexASecret();
  ASSERT_NE(entry, nullptr);

  EXPECT_EQ(ShipPairingBuildMessage(nullptr), nullptr);
  EXPECT_EQ(ShipPairingCalcDigest(nullptr, secret.data(), secret.size()), nullptr);
  EXPECT_EQ(ShipPairingCalcDigest(entry.get(), nullptr, secret.size()), nullptr);
  EXPECT_EQ(ShipPairingCalcDigest(entry.get(), secret.data(), 0), nullptr);
  EXPECT_FALSE(ShipPairingVerifyDigest(nullptr, secret.data(), secret.size()));

  // A secret longer than the specified 128 bit would not fit the key it is
  // concatenated into.
  const std::vector<uint8_t> oversized(SHIP_PAIRING_SECRET_SIZE + 1, 0x00);
  EXPECT_EQ(ShipPairingCalcDigest(entry.get(), oversized.data(), oversized.size()), nullptr);
}
