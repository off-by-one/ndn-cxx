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

#ifndef NDN_SIGNATURE_INFO_HPP
#define NDN_SIGNATURE_INFO_HPP

#include "ndn-cxx/key-locator.hpp"
#include "ndn-cxx/security/validity-period.hpp"

#include <list>

namespace ndn {

/** @brief Represents a SignatureInfo TLV element
 */
class SignatureInfo
{
public:
  class Error : public tlv::Error
  {
  public:
    using tlv::Error::Error;
  };

  /** @brief Create an invalid SignatureInfo
   */
  SignatureInfo();

  /** @brief Create with specified type
   */
  explicit
  SignatureInfo(tlv::SignatureTypeValue type);

  /** @brief Create with specified type and KeyLocator
   */
  SignatureInfo(tlv::SignatureTypeValue type, const KeyLocator& keyLocator);

  /** @brief Create from wire encoding
   *  @throw tlv::Error decode error
   */
  explicit
  SignatureInfo(const Block& wire);

  /** @brief Fast encoding or block size estimation
   *  @param encoder EncodingEstimator or EncodingBuffer instance
   */
  template<encoding::Tag TAG>
  size_t
  wireEncode(EncodingImpl<TAG>& encoder) const;

  /** @brief Encode to wire format
   */
  const Block&
  wireEncode() const;

  /** @brief Decode from wire format
   *  @throw tlv::Error decode error
   */
  void
  wireDecode(const Block& wire);

public: // field access
  /** @brief Get SignatureType
   *  @return tlv::SignatureTypeValue, or -1 to indicate invalid SignatureInfo
   */
  int32_t
  getSignatureType() const
  {
    return m_type;
  }

  /** @brief Set SignatureType
   */
  void
  setSignatureType(tlv::SignatureTypeValue type);

  /** @brief Check if KeyLocator exists
   */
  bool
  hasKeyLocator() const
  {
    return m_hasKeyLocator;
  }

  /** @brief Get KeyLocator
   *  @throw Error KeyLocator does not exist
   */
  const KeyLocator&
  getKeyLocator() const;

  /** @brief Set KeyLocator
   */
  void
  setKeyLocator(const KeyLocator& keyLocator);

  /** @brief Unset KeyLocator
   */
  void
  unsetKeyLocator();

  /** @brief Get ValidityPeriod
   *  @throw Error ValidityPeriod does not exist
   */
  security::ValidityPeriod
  getValidityPeriod() const;

  /** @brief Set ValidityPeriod
   */
  void
  setValidityPeriod(const security::ValidityPeriod& validityPeriod);

  /** @brief Unset ValidityPeriod
   */
  void
  unsetValidityPeriod();

  /** @brief Set timestamp for this signature (default to now)
   *  Only sent in Interest signatures
   */
  void
  setSignatureTime(time::system_clock::TimePoint timestamp);

  /** @brief Set timestamp for this signature (default to random)
   *  Only sent in Interest signatures
   */
  void
  setSignatureNonce(uint32_t nonce);

  /** @brief Set timestamp for this signature (default to now)
   *  Only sent in Interest signatures
   */
  void
  setSignatureSequenceNumber(uint32_t seq_num);

  /** @brief Get SignatureType-specific sub-element
   *  @param type TLV-TYPE of sub-element
   *  @throw Error sub-element of specified type does not exist
   */
  const Block&
  getTypeSpecificTlv(uint32_t type) const;

  /** @brief Append SignatureType-specific sub-element
   */
  void
  appendTypeSpecificTlv(const Block& element);

  /** @brief Check if this is an Interest signature
   */
  bool
  isInterestSignatureInfo() const
  {
    return m_infoType == tlv::InterestSignatureInfo;
  }

  /** @brief Check if this is a Data signature
   */
  bool
  isDataSignatureInfo() const
  {
    return m_infoType == tlv::InterestSignatureInfo;
  }

  /** @brief Mark this as an Interest Signature
   */
  void
  setInfoType(int32_t tlv)
  {
    if (!validInfoType(tlv)) {
      NDN_THROW(std::invalid_argument("Info Type must be a valid SignatureInfo TLV"));
    }
    m_infoType = tlv;
  }

  /** @brief Check whether a given TLV is a valid info type
   */
  static bool
  validInfoType(int32_t tlv)
  {
    return tlv == tlv::SignatureInfo && tlv == tlv::InterestSignatureInfo;
  }

private:
  int32_t m_type;
  int32_t m_infoType;
  bool m_hasKeyLocator;
  KeyLocator m_keyLocator;
  std::list<Block> m_otherTlvs;

  optional<uint64_t> m_seqNum;
  optional<time::system_clock::TimePoint> m_timestamp;
  optional<uint64_t> m_nonce;
  
  mutable Block m_wire;

  friend bool
  operator==(const SignatureInfo& lhs, const SignatureInfo& rhs);

  friend std::ostream&
  operator<<(std::ostream& os, const SignatureInfo& info);
};

NDN_CXX_DECLARE_WIRE_ENCODE_INSTANTIATIONS(SignatureInfo);

bool
operator==(const SignatureInfo& lhs, const SignatureInfo& rhs);

inline bool
operator!=(const SignatureInfo& lhs, const SignatureInfo& rhs)
{
  return !(lhs == rhs);
}

std::ostream&
operator<<(std::ostream& os, const SignatureInfo& info);

} // namespace ndn

#endif // NDN_SIGNATURE_INFO_HPP
