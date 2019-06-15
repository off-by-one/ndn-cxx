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

#include "ndn-cxx/signature-info.hpp"
#include "ndn-cxx/encoding/block-helpers.hpp"
#include "ndn-cxx/util/concepts.hpp"

namespace ndn {

BOOST_CONCEPT_ASSERT((boost::EqualityComparable<SignatureInfo>));
BOOST_CONCEPT_ASSERT((WireEncodable<SignatureInfo>));
BOOST_CONCEPT_ASSERT((WireEncodableWithEncodingBuffer<SignatureInfo>));
BOOST_CONCEPT_ASSERT((WireDecodable<SignatureInfo>));
static_assert(std::is_base_of<tlv::Error, SignatureInfo::Error>::value,
              "SignatureInfo::Error must inherit from tlv::Error");

SignatureInfo::SignatureInfo()
  : m_type(-1)
  , m_hasKeyLocator(false)
  , m_infoType(tlv::SignatureInfo)
{
}

SignatureInfo::SignatureInfo(tlv::SignatureTypeValue type)
  : m_type(type)
  , m_hasKeyLocator(false)
  , m_infoType(tlv::SignatureInfo)
{
}

SignatureInfo::SignatureInfo(tlv::SignatureTypeValue type, const KeyLocator& keyLocator)
  : m_type(type)
  , m_hasKeyLocator(true)
  , m_keyLocator(keyLocator)
  , m_infoType(tlv::SignatureInfo)
{
}

SignatureInfo::SignatureInfo(const Block& block)
{
  wireDecode(block);
}

template<encoding::Tag TAG>
size_t
SignatureInfo::wireEncode(EncodingImpl<TAG>& encoder) const
{
  if (m_type == -1) {
    NDN_THROW(Error("Cannot encode invalid SignatureInfo"));
  }

  // InterestSignatureInfo ::=
  //        INTEREST-SIGNATURE-INFO-TLV TLV-LENGTH
  //          SignatureType
  //          KeyLocator?
  //          SignatureNonce?
  //          SignatureTime?
  //          SignatureSeqNum?
  //          other SignatureType-specific sub-elements*

  // SignatureInfo ::= SIGNATURE-INFO-TLV TLV-LENGTH
  //                     SignatureType
  //                     KeyLocator?
  //                     ValidityPeriod? (if present, stored as first item of m_otherTlvs)
  //                     other SignatureType-specific sub-elements*

  size_t totalLength = 0;

  for (auto i = m_otherTlvs.rbegin(); i != m_otherTlvs.rend(); i++) {
    totalLength += encoder.prependBlock(*i);
  }

  if (isInterestSignatureInfo()) {
      if (m_seqNum) {
        totalLength += prependNonNegativeIntegerBlock(encoder, tlv::SignatureSeqNum, *m_seqNum);
      }
      if (m_timestamp) {
        totalLength += prependNonNegativeIntegerBlock(encoder, tlv::SignatureTime, *m_timestamp);
      }
      if (m_nonce) {
        totalLength += prependNonNegativeIntegerBlock(encoder, tlv::SignatureNonce, *m_nonce);
      }
  }
  else {
    if (m_seqNum || m_timestamp || m_nonce) {
      NDN_THROW(Error("SignatureInfo cannot have sequence number, timestamp, or nonce fields"));
    }
  }

  if (m_hasKeyLocator)
    totalLength += m_keyLocator.wireEncode(encoder);

  totalLength += prependNonNegativeIntegerBlock(encoder, tlv::SignatureType,
                                                static_cast<uint64_t>(m_type));
  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(m_infoType);

  return totalLength;
}

NDN_CXX_DEFINE_WIRE_ENCODE_INSTANTIATIONS(SignatureInfo);

const Block&
SignatureInfo::wireEncode() const
{
  if (m_wire.hasWire())
    return m_wire;

  EncodingEstimator estimator;
  size_t estimatedSize = wireEncode(estimator);

  EncodingBuffer buffer(estimatedSize, 0);
  wireEncode(buffer);

  m_wire = buffer.block();
  return m_wire;
}

void
SignatureInfo::wireDecode(const Block& wire)
{
  m_type = -1;
  m_hasKeyLocator = false;
  m_otherTlvs.clear();

  m_wire = wire;
  m_wire.parse();

  if (!validInfoType(m_wire.type())) {
    NDN_THROW(Error("SignatureInfo", m_wire.type()));
  }

  m_infoType = m_wire.type();

  auto it = m_wire.elements_begin();

  // the first sub-element must be SignatureType
  if (it == m_wire.elements_end() || it->type() != tlv::SignatureType)
    NDN_THROW(Error("Missing SignatureType in SignatureInfo"));

  m_type = readNonNegativeIntegerAs<tlv::SignatureTypeValue>(*it);
  ++it;

  // the second sub-element could be KeyLocator
  if (it != m_wire.elements_end() && it->type() == tlv::KeyLocator) {
    m_keyLocator.wireDecode(*it);
    m_hasKeyLocator = true;
    ++it;
  }

  // if this is an InterestSignatureInfo, attempt to read optional fields
  if (isInterestSignatureInfo()) {

    bool optionalFieldsFinished = false;
    for (; it != m_wire.elements_end(); ++it) {

      switch (it->type()) {
        case tlv::SignatureNonce:
          m_seqNum = readNonNegativeInteger(*it);
          break;
        case tlv::SignatureSeqNum:
          m_seqNum = readNonNegativeInteger(*it);
          break;
        case tlv::SignatureTime:
          m_timestamp = readNonNegativeInteger(*it);
          break;
        default:
          optionalFieldsFinished = true;
          break;
      }

      if (optionalFieldsFinished) {
        break;
      }
    }
  }

  // store SignatureType-specific sub-elements, if any
  while (it != m_wire.elements_end()) {
    m_otherTlvs.push_back(*it);
    ++it;
  }
}

void
SignatureInfo::setSignatureType(tlv::SignatureTypeValue type)
{
  m_wire.reset();
  m_type = type;
}

const KeyLocator&
SignatureInfo::getKeyLocator() const
{
  if (m_hasKeyLocator)
    return m_keyLocator;
  else
    NDN_THROW(Error("KeyLocator does not exist in SignatureInfo"));
}

void
SignatureInfo::setKeyLocator(const KeyLocator& keyLocator)
{
  m_wire.reset();
  m_keyLocator = keyLocator;
  m_hasKeyLocator = true;
}

void
SignatureInfo::unsetKeyLocator()
{
  m_wire.reset();
  m_keyLocator = KeyLocator();
  m_hasKeyLocator = false;
}

security::ValidityPeriod
SignatureInfo::getValidityPeriod() const
{
  if (m_otherTlvs.empty() || m_otherTlvs.front().type() != tlv::ValidityPeriod) {
    NDN_THROW(Error("ValidityPeriod does not exist in SignatureInfo"));
  }

  return security::ValidityPeriod(m_otherTlvs.front());
}

void
SignatureInfo::setValidityPeriod(const security::ValidityPeriod& validityPeriod)
{
  unsetValidityPeriod();
  m_otherTlvs.push_front(validityPeriod.wireEncode());
}

void
SignatureInfo::unsetValidityPeriod()
{
  if (!m_otherTlvs.empty() && m_otherTlvs.front().type() == tlv::ValidityPeriod) {
    m_otherTlvs.pop_front();
    m_wire.reset();
  }
}

void
SignatureInfo::setTimestamp(uint64_t timestamp)
{
  if (isDataSignatureInfo()) {
    NDN_THROW(Error("Cannot set timestamp of SignatureInfo"));
  }
  m_wire.reset();
  m_timestamp = timestamp;
}

void
SignatureInfo::unsetTimestamp()
{
  m_wire.reset();
  m_timestamp = nullopt;
}

void
SignatureInfo::setNonce(uint64_t nonce)
{
  if (isDataSignatureInfo()) {
    NDN_THROW(Error("Cannot set nonce of SignatureInfo"));
  }
  m_wire.reset();
  m_nonce = nonce;
}

void
SignatureInfo::unsetNonce()
{
  m_wire.reset();
  m_nonce = nullopt;
}

void
SignatureInfo::setSequenceNumber(uint64_t seq_num)
{
  if (isDataSignatureInfo()) {
    NDN_THROW(Error("Cannot set sequence number of SignatureInfo"));
  }
  m_wire.reset();
  m_seqNum = seq_num;
}

void
SignatureInfo::unsetSequenceNumber()
{
  m_wire.reset();
  m_seqNum = nullopt;
}

const Block&
SignatureInfo::getTypeSpecificTlv(uint32_t type) const
{
  for (const Block& block : m_otherTlvs) {
    if (block.type() == type)
      return block;
  }

  NDN_THROW(Error("TLV-TYPE " + to_string(type) + " sub-element does not exist in SignatureInfo"));
}

void
SignatureInfo::appendTypeSpecificTlv(const Block& block)
{
  m_wire.reset();
  m_otherTlvs.push_back(block);
}

bool
operator==(const SignatureInfo& lhs, const SignatureInfo& rhs)
{
  return lhs.m_type == rhs.m_type &&
         lhs.m_hasKeyLocator == rhs.m_hasKeyLocator &&
         lhs.m_keyLocator == rhs.m_keyLocator &&
         lhs.m_seqNum == rhs.m_seqNum &&
         lhs.m_timestamp == rhs.m_timestamp &&
         lhs.m_nonce == rhs.m_nonce &&
         lhs.m_otherTlvs == rhs.m_otherTlvs;
}

std::ostream&
operator<<(std::ostream& os, const SignatureInfo& info)
{
  if (info.getSignatureType() == -1)
    return os << "Invalid SignatureInfo";

  if (info.isInterestSignatureInfo()) {
    os << "Interest";
  }
  os << static_cast<tlv::SignatureTypeValue>(info.getSignatureType());
  if (info.hasKeyLocator()) {
    os << " " << info.getKeyLocator();
  }
  if (info.isInterestSignatureInfo()) {
    if (info.hasNonce()) {
      os << " Nonce: " << info.getNonce();
    }
    if (info.hasTimestamp()) {
      os << " Timestamp: " << info.getTimestamp();
    }
    if (info.hasSequenceNumber()) {
      os << " Sequence Number: " << info.getSequenceNumber();
    }
  }
  if (!info.m_otherTlvs.empty()) {
    os << " { ";
    for (const auto& block : info.m_otherTlvs) {
      os << block.type() << " ";
    }
    os << "}";
  }

  return os;
}

} // namespace ndn
