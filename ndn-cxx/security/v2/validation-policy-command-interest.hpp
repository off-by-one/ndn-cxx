/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2013-2018 Regents of the University of California.
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

#ifndef NDN_SECURITY_V2_VALIDATION_POLICY_COMMAND_INTEREST_HPP
#define NDN_SECURITY_V2_VALIDATION_POLICY_COMMAND_INTEREST_HPP

#include "ndn-cxx/security/v2/validation-policy.hpp"

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/multi_index/key_extractors.hpp>

namespace ndn {
namespace security {
namespace v2 {

/** \brief Validation policy for stop-and-wait command Interests
 *  \sa https://redmine.named-data.net/projects/ndn-cxx/wiki/CommandInterest
 *
 *  This policy checks the timestamp field of a stop-and-wait command Interest.
 *  Signed Interest validation and Data validation requests are delegated to an inner policy.
 */
class ValidationPolicyCommandInterest : public ValidationPolicy
{
public:
  class Options
  {
  public:
    Options()
    {
    }

  public: // per-field configuration
    /** \brief specify whether timestamp should be checked
     *
     * By default all signed interests are required to have a timestamp
     */
    bool requireTimestamp = true;

    /** \brief tolerance of initial timestamp
     *
     *  A stop-and-wait command Interest is considered "initial" if the validator
     *  has not recorded the last timestamp from the same public key, or when
     *  such knowledge has been erased.
     *  For an initial command Interest, its timestamp is compared to the current
     *  system clock, and the command Interest is rejected if the absolute difference
     *  is greater than the grace interval.
     *
     *  This should be positive.
     *  Setting this option to 0 or negative causes the validator to require exactly same
     *  timestamp as the system clock, which most likely rejects all command Interests.
     */
    time::nanoseconds gracePeriod = 2_min;

    /* Specify whether sequence number should be checked
     * By default signed interests are not required to have a sequence number
     */
    bool requireSequenceNumber = false;

    /* Specify whether nonce should be checked
     * By default signed interests are not required to have a nonce
     */
    bool requireNonce = false;

    /* Specify maximum number of nonce records per key to store
     */
    ssize_t maxNonceRecords = 1000;

  public: // record lifetime / amount configuration

    /** \brief max number of distinct public keys of which to record replay data
     *
     *  The validator records last timestamps, sequence numbers, and a
     *  collection of nonces for every public key.  For a subsequent command
     *  Interest using the same public key, its replay data is compared to the
     *  last updated replay data from that public key, and the command Interest
     *  is rejected if it lacks any required fields or fails the requisite
     *  checks (newer timestamp, higher sequence number, and new nonce).
     *
     *  This option limits the number of distinct public keys being tracked.
     *  If the limit is exceeded, the oldest record is deleted.
     *
     *  Setting this option to -1 allows tracking unlimited public keys.
     *  Setting this option to 0 disables last timestamp records and causes
     *  every command Interest to be processed as initial.
     */
    ssize_t maxRecords = 1000;

    /** \brief max lifetime of a replay record
     *
     *  A record expires and can be deleted if it has not been refreshed
     *  within this duration.
     *  Setting this option to 0 or negative makes records expire immediately
     *  and causes every command Interest to be processed as initial.
     */
    time::nanoseconds recordLifetime = 1_h;
  };

  /** \brief constructor
   *  \param inner a Validator for signed Interest signature validation and Data validation;
   *               this must not be nullptr
   *  \param options stop-and-wait command Interest validation options
   *  \throw std::invalid_argument inner policy is nullptr
   */
  explicit
  ValidationPolicyCommandInterest(unique_ptr<ValidationPolicy> inner,
                                  const Options& options = {});

protected:
  void
  checkPolicy(const Data& data, const shared_ptr<ValidationState>& state,
              const ValidationContinuation& continueValidation) override;

  void
  checkPolicy(const Interest& interest, const shared_ptr<ValidationState>& state,
              const ValidationContinuation& continueValidation) override;

private:
  void
  cleanup();

  std::tuple<bool, Name, uint64_t>
  parseCommandInterest(const Interest& interest, const shared_ptr<ValidationState>& state) const;

  bool
  checkTimestamp(const shared_ptr<ValidationState>& state,
                 const Name& keyName, uint64_t timestamp);

  void
  insertNewTimeRecord(const Name& keyName, uint64_t timestamp);

private:
  Options m_options;

  using NonceContainer = boost::multi_index_container<
    uint64_t,
    boost::multi_index::indexed_by<
      boost::multi_index::hashed_unique<boost::multi_index::identity<uint64_t>>,
      boost::multi_index::sequenced<>
    >
  >;
  using NonceIndex = NonceContainer::nth_index<0>::type;
  using NonceQueue = NonceContainer::nth_index<1>::type;

  struct NonceRecords{
    NonceRecords()
      : index(container.get<0>())
      , queue(container.get<1>())
    {
    }

    NonceContainer container;
    NonceIndex& index;
    NonceQueue& queue;
  };

  struct ReplayRecord
  {
    Name keyName;

    uint64_t timestamp;
    uint64_t seqNum;
    NonceRecords nonces;

    time::steady_clock::TimePoint lastRefreshed;
  };

  using Container = boost::multi_index_container<
    ReplayRecord,
    boost::multi_index::indexed_by<
      boost::multi_index::ordered_unique<
        boost::multi_index::member<ReplayRecord, Name, &ReplayRecord::keyName>
      >,
      boost::multi_index::sequenced<>
    >
  >;
  using Index = Container::nth_index<0>::type;
  using Queue = Container::nth_index<1>::type;

  Container m_container;
  Index& m_index;
  Queue& m_queue;
};

} // namespace v2
} // namespace security
} // namespace ndn

#endif // NDN_SECURITY_V2_VALIDATION_POLICY_COMMAND_INTEREST_HPP
