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

#include "ndn-cxx/security/v2/validation-policy-command-interest.hpp"

namespace ndn {
namespace security {
namespace v2 {

ValidationPolicyCommandInterest::ValidationPolicyCommandInterest(unique_ptr<ValidationPolicy> inner,
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
ValidationPolicyCommandInterest::checkPolicy(const Data& data, const shared_ptr<ValidationState>& state,
                                             const ValidationContinuation& continueValidation)
{
  getInnerPolicy().checkPolicy(data, state, continueValidation);
}

void
ValidationPolicyCommandInterest::checkPolicy(const Interest& interest, const shared_ptr<ValidationState>& state,
                                             const ValidationContinuation& continueValidation)
{
  if (!interest.hasSignature()) {
    state->fail({ValidationError::POLICY_ERROR, "Interest is not signed"});
    return;
  }

  SignatureInfo info = interest.getSignature().getSignatureInfo();
  Name keyName = getKeyLocatorName(interest, *state);

  if (m_options.checkTimestamp) {
    uint64_t timestamp = toUnixTimestamp(info.getTime()).count();

    if (!checkTimestamp(state, keyName, timestamp)) {
      return;
    }
  }
  getInnerPolicy().checkPolicy(interest, state, std::bind(continueValidation, _1, _2));
}

void
ValidationPolicyCommandInterest::cleanupTimestamps()
{
  auto expiring = time::steady_clock::now() - m_options.timestampRecordLifetime;

  while ((!m_tqueue.empty() && m_tqueue.front().lastRefreshed <= expiring) ||
         (m_options.maxTimestampRecords >= 0 &&
          m_tqueue.size() > static_cast<size_t>(m_options.maxTimestampRecords))) {
    m_tqueue.pop_front();
  }
}


bool
ValidationPolicyCommandInterest::checkTimestamp(const shared_ptr<ValidationState>& state,
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
ValidationPolicyCommandInterest::insertNewTimeRecord(const Name& keyName, uint64_t timestamp)
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

} // namespace v2
} // namespace security
} // namespace ndn
