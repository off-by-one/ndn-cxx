/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2013-2019 Regents of the University of California.
 *
 * This file is part of ndn-cxx library (NDN C++ library with eXperimental eXtensions).
 *
 * ndn-cxx library is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * ndn-cxx library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received copies of the GNU General Public License and GNU Lesser
 * General Public License along with ndn-cxx, e.g., in COPYING.md file.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndn-cxx authors and contributors.
 */

#include "ndn-cxx/security/v2/validation-policy-signed-interest.hpp"
#include "ndn-cxx/security/verification-helpers.hpp"
#include "ndn-cxx/security/security-common.hpp"

namespace ndn {
namespace security {
namespace v2 {

ValidationPolicySignedInterest::ValidationPolicySignedInterest(unique_ptr<ValidationPolicy> inner,
                                                                 const Options& options)
  : m_options(options)
  , m_tindex(m_tcontainer.get<0>())
  , m_tqueue(m_tcontainer.get<1>())
  , m_sindex(m_scontainer.get<0>())
  , m_squeue(m_scontainer.get<1>())
  , m_nindex(m_ncontainer.get<0>())
  , m_nqueue(m_ncontainer.get<1>())
{
  if (inner == nullptr) {
    NDN_THROW(std::invalid_argument("inner policy is missing"));
  }
  setInnerPolicy(std::move(inner));

  m_options.gracePeriod = std::max(m_options.gracePeriod, 0_ns);
}

void
ValidationPolicySignedInterest::checkPolicy(const Data& data, const shared_ptr<ValidationState>& state,
                                             const ValidationContinuation& continueValidation)
{
  getInnerPolicy().checkPolicy(data, state, continueValidation);
}

void
ValidationPolicySignedInterest::checkPolicy(const Interest& interest, const shared_ptr<ValidationState>& state,
                                             const ValidationContinuation& continueValidation)
{
  if (!interest.hasSignature()) {
    state->fail({ValidationError::POLICY_ERROR, "Interest is not signed"});
    return;
  }

  ConstBufferPtr suffix = interest.wireEncodeParametersSuffix();

  const name::Component& digestComponent = interest.getName().get(-1);
  if (!digestComponent.isParametersSha256Digest()) {
    state->fail({ValidationError::POLICY_ERROR, "Interest has no parameters hash"});
    return;
  }

  const Block& digestBlock = digestComponent.wireEncode();
  bool digestOk = verifyDigest(suffix->get<uint8_t>(),
                               suffix->size(),
                               digestBlock.value(),
                               digestBlock.value_size(),
                               DigestAlgorithm::SHA256);

  if (!digestOk) {
    state->fail({ValidationError::POLICY_ERROR, "Parameters hash does not match"});
    return;
  }

  SignatureInfo info = interest.getSignature().getSignatureInfo();
  Name keyName = getKeyLocatorName(interest, *state);

  if (m_options.checkTimestamp) {
    if (!info.hasTimestamp()) {
      state->fail({ValidationError::POLICY_ERROR, "Interest has no timestamp"});
      return;
    }

    uint64_t timestamp = info.getTimestamp();

    if (!checkTimestamp(state, keyName, timestamp)) {
      return;
    }
  }

  if (m_options.checkSequenceNumber) {
    if (!info.hasSequenceNumber()) {
      state->fail({ValidationError::POLICY_ERROR, "Interest has no sequence number"});
      return;
    }

    if (!checkSequenceNumber(state, keyName, info.getSequenceNumber())) {
      return;
    }
  }

  if (m_options.checkNonce) {
    if (!info.hasNonce()) {
      state->fail({ValidationError::POLICY_ERROR, "Interest has no nonce"});
      return;
    }

    if (!checkNonce(state, keyName, info.getNonce())) {
      return;
    }
  }

  getInnerPolicy().checkPolicy(interest, state, std::bind(continueValidation, _1, _2));
}

void
ValidationPolicySignedInterest::cleanupTimestamps()
{
  auto expiring = time::steady_clock::now() - m_options.timestampRecordLifetime;

  while ((!m_tqueue.empty() && m_tqueue.front().lastRefreshed <= expiring) ||
         (m_options.maxTimestampRecords >= 0 &&
          m_tqueue.size() > static_cast<size_t>(m_options.maxTimestampRecords))) {
    m_tqueue.pop_front();
  }
}

bool
ValidationPolicySignedInterest::checkTimestamp(const shared_ptr<ValidationState>& state,
                                                const Name& keyName, uint64_t timestamp)
{
  this->cleanupTimestamps();

  auto now = time::system_clock::now();
  auto timestampPoint = time::fromUnixTimestamp(time::milliseconds(timestamp));
  if (timestampPoint < now - m_options.gracePeriod || timestampPoint > now + m_options.gracePeriod) {
    state->fail({ValidationError::POLICY_ERROR,
                 "Time is outside the grace period for key " + keyName.toUri()});
    return false;
  }

  auto it = m_tindex.find(keyName);
  if (it != m_tindex.end()) {
    if (timestamp <= it->timestamp) {
      state->fail({ValidationError::POLICY_ERROR,
                   "Time is reordered for key " + keyName.toUri()});
      return false;
    }
  }

  auto interestState = dynamic_pointer_cast<InterestValidationState>(state);
  BOOST_ASSERT(interestState != nullptr);
  interestState->afterSuccess.connect([=] (const Interest&) { insertNewTimeRecord(keyName, timestamp); });
  return true;
}

void
ValidationPolicySignedInterest::insertNewTimeRecord(const Name& keyName, uint64_t timestamp)
{
  // try to insert new record
  auto now = time::steady_clock::now();
  auto i = m_tqueue.end();
  bool isNew = false;
  LastTimestampRecord newRecord{keyName, timestamp, now};
  std::tie(i, isNew) = m_tqueue.push_back(newRecord);

  if (!isNew) {
    BOOST_ASSERT(i->keyName == keyName);

    // set lastRefreshed field, and move to queue tail
    m_tqueue.erase(i);
    isNew = m_tqueue.push_back(newRecord).second;
    BOOST_VERIFY(isNew);
  }
}

void
ValidationPolicySignedInterest::cleanupSequenceNumbers()
{
  auto expiring = time::steady_clock::now() - m_options.timestampRecordLifetime;

  while ((!m_squeue.empty() && m_squeue.front().lastRefreshed <= expiring) ||
         (m_options.maxSequenceNumberRecords >= 0 &&
          m_squeue.size() > static_cast<size_t>(m_options.maxSequenceNumberRecords))) {
    m_squeue.pop_front();
  }
}

bool
ValidationPolicySignedInterest::checkSequenceNumber(
  const shared_ptr<ValidationState>& state,
  const Name& keyName,
  uint64_t seq_num)
{
  this->cleanupTimestamps();

  auto it = m_sindex.find(keyName);
  if (it != m_sindex.end()) {
    if (seq_num <= it->seq_num) {
      state->fail({ValidationError::POLICY_ERROR,
                   "Sequenec Number is reordered for key " + keyName.toUri()});
      return false;
    }
  }

  auto interestState = dynamic_pointer_cast<InterestValidationState>(state);
  BOOST_ASSERT(interestState != nullptr);
  interestState->afterSuccess.connect([=] (const Interest&) { insertNewSequenceRecord(keyName, seq_num); });
  return true;
}

void
ValidationPolicySignedInterest::insertNewSequenceRecord(const Name& keyName, uint64_t seq_num)
{
  // try to insert new record
  auto now = time::steady_clock::now();
  auto i = m_squeue.end();
  bool isNew = false;
  LastSequenceRecord newRecord{keyName, seq_num, now};
  std::tie(i, isNew) = m_squeue.push_back(newRecord);

  if (!isNew) {
    BOOST_ASSERT(i->keyName == keyName);

    // set lastRefreshed field, and move to queue tail
    m_squeue.erase(i);
    isNew = m_squeue.push_back(newRecord).second;
    BOOST_VERIFY(isNew);
  }
}

void
ValidationPolicySignedInterest::cleanupNonces()
{
  auto expiring = time::steady_clock::now() - m_options.nonceRecordLifetime;

  while ((!m_nqueue.empty() && m_nqueue.front().timeAdded <= expiring) ||
         (m_options.maxNonceRecords >= 0 &&
          m_nqueue.size() > static_cast<size_t>(m_options.maxNonceRecords))) {
    m_nqueue.pop_front();
  }
}

bool
ValidationPolicySignedInterest::checkNonce(const shared_ptr<ValidationState>& state,
                                            const Name& keyName, uint64_t nonce)
{
  this->cleanupNonces();

  NonceIndex::iterator start;
  NonceIndex::iterator end;
  boost::tie(start, end) = m_nindex.equal_range(nonce);

  for ( ; start != end ; start++) {
    if (keyName == start->keyName) {
      state->fail({ValidationError::POLICY_ERROR,
                   "Nonce is repeated for key " + keyName.toUri()});
      return false;
    }
  }

  auto interestState = dynamic_pointer_cast<InterestValidationState>(state);
  BOOST_ASSERT(interestState != nullptr);
  interestState->afterSuccess.connect([=] (const Interest&) { insertNewNonceRecord(keyName, nonce); });
  return true;
}

void
ValidationPolicySignedInterest::insertNewNonceRecord(const Name& keyName, uint64_t nonce)
{
  // try to insert new record
  auto now = time::steady_clock::now();
  auto i = m_nqueue.end();
  bool isNew = false;
  NonceRecord newRecord{keyName, nonce, now};
  std::tie(i, isNew) = m_nqueue.push_back(newRecord);
}

} // namespace v2
} // namespace security
} // namespace ndn
