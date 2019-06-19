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

#ifndef NDN_SECURITY_V2_VALIDATION_POLICY_SIGNED_INTEREST_HPP
#define NDN_SECURITY_V2_VALIDATION_POLICY_SIGNED_INTEREST_HPP

#include "ndn-cxx/security/v2/validation-policy.hpp"

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/multi_index/key_extractors.hpp>

namespace ndn {
namespace security {
namespace v2 {

/** \brief Validation policy for signed interests
 *  \sa http://named-data.net/doc/NDN-packet-spec/current/signed-interest.html
 *
 *  Signature Interest validation and Data validation requests are delegated to an inner policy.
 */
class ValidationPolicySignedInterest : public ValidationPolicy
{

public:
  class Options
  {
  friend class ValidationPolicySignedInterest;

  public:
    Options(bool checkNonce, bool checkTimestamp, bool checkSequenceNumber)
      : checkNonce(checkNonce)
      , checkTimestamp(checkTimestamp)
      , checkSequenceNumber(checkSequenceNumber)
    {
    }

  public: // Timestamp options
    /** 
     * Tolerance of a timestamp to the current time
     */
    time::nanoseconds gracePeriod = 2_min;

    /**
     * Maximum number of timestamp records allowed
     * When exceeded, the oldest records are evicted
     */
    ssize_t maxTimestampRecords = 1000;

    /**
     * Maximum lifetime of a single record
     * Older records (even under the maximum number) are evicted
     */
    time::nanoseconds timestampRecordLifetime = 1_h;

  public: // Sequence Number options
    /**
     * Maximum number of sequence number records allowed
     * When exceeded, the oldest records are evicted
     */
    ssize_t maxSequenceNumberRecords = 1000;

    /**
     * Maximum lifetime of a single record
     * Older records (even under the maximum number) are evicted
     */
    time::nanoseconds sequenceNumberRecordLifetime = 1_h;

  public: // Nonce options
    /**
     * Maximum number of nonce records allowed
     *
     * When exceeded, the oldest records are evicted
     *
     * Note that these records are not unique per key, so frequently-sending
     * keys can evict valid records for infrequently sending keys faster than
     * expected
     */
    ssize_t maxNonceRecords = 1000;

    /**
     * Maximum lifetime of a single record
     * Older records (even under the maximum number) are evicted
     */
    time::nanoseconds nonceRecordLifetime = 1_h;

  private:
    bool checkNonce = false;
    bool checkTimestamp = true;
    bool checkSequenceNumber = false;
  };

  /** \brief constructor
   *  \param inner a Validator for signed Interest signature validation and Data validation;
   *               this must not be nullptr
   *  \param options stop-and-wait command Interest validation options
   *  \throw std::invalid_argument inner policy is nullptr
   */
  explicit
  ValidationPolicySignedInterest(unique_ptr<ValidationPolicy> inner,
                                  const Options& options = {false, false, false});

protected:
  void
  checkPolicy(const Data& data, const shared_ptr<ValidationState>& state,
              const ValidationContinuation& continueValidation) override;

  void
  checkPolicy(const Interest& interest, const shared_ptr<ValidationState>& state,
              const ValidationContinuation& continueValidation) override;

private:
  void
  cleanupTimestamps();

  bool
  checkTimestamp(const shared_ptr<ValidationState>& state,
                 const Name& keyName, uint64_t timestamp);

  void
  insertNewTimeRecord(const Name& keyName, uint64_t timestamp);

  void
  cleanupSequenceNumbers();

  bool
  checkSequenceNumber(const shared_ptr<ValidationState>& state,
                      const Name& keyName, uint64_t sequenceNumber);

  void
  insertNewSequenceRecord(const Name& keyName, uint64_t sequenceNumber);

  void
  cleanupNonces();

  bool
  checkNonce(const shared_ptr<ValidationState>& state,
                      const Name& keyName, uint64_t sequenceNumber);

  void
  insertNewNonceRecord(const Name& keyName, uint64_t sequenceNumber);

private:
  Options m_options;

  struct LastTimestampRecord
  {
    Name keyName;
    uint64_t timestamp;
    time::steady_clock::TimePoint lastRefreshed;
  };

  using TimeContainer = boost::multi_index_container<
    LastTimestampRecord,
    boost::multi_index::indexed_by<
      boost::multi_index::ordered_unique<
        boost::multi_index::member<LastTimestampRecord, Name, &LastTimestampRecord::keyName>
      >,
      boost::multi_index::sequenced<>
    >
  >;
  using TimeIndex = TimeContainer::nth_index<0>::type;
  using TimeQueue = TimeContainer::nth_index<1>::type;

  TimeContainer m_tcontainer;
  TimeIndex& m_tindex;
  TimeQueue& m_tqueue;

  struct LastSequenceRecord
  {
    Name keyName;
    uint64_t seq_num;
    time::steady_clock::TimePoint lastRefreshed;
  };

  using SequenceContainer = boost::multi_index_container<
    LastSequenceRecord,
    boost::multi_index::indexed_by<
      boost::multi_index::ordered_unique<
        boost::multi_index::member<LastSequenceRecord, Name, &LastSequenceRecord::keyName>
      >,
      boost::multi_index::sequenced<>
    >
  >;
  using SequenceIndex = SequenceContainer::nth_index<0>::type;
  using SequenceQueue = SequenceContainer::nth_index<1>::type;

  SequenceContainer m_scontainer;
  SequenceIndex& m_sindex;
  SequenceQueue& m_squeue;

  struct NonceRecord
  {
    Name keyName;
    uint64_t nonce;
    time::steady_clock::TimePoint timeAdded;
  };

  using NonceContainer = boost::multi_index_container<
    NonceRecord,
    boost::multi_index::indexed_by<
      boost::multi_index::hashed_non_unique<
        boost::multi_index::member<NonceRecord, uint64_t, &NonceRecord::nonce>
      >,
      boost::multi_index::sequenced<>
    >
  >;
  using NonceIndex = NonceContainer::nth_index<0>::type;
  using NonceQueue = NonceContainer::nth_index<1>::type;

  NonceContainer m_ncontainer;
  NonceIndex& m_nindex;
  NonceQueue& m_nqueue;
};

} // namespace v2
} // namespace security
} // namespace ndn

#endif // NDN_SECURITY_V2_VALIDATION_POLICY_SIGNED_INTEREST_HPP
