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

#include "ndn-cxx/interest.hpp"
#include "ndn-cxx/data.hpp"
#include "ndn-cxx/util/random.hpp"

#include <boost/scope_exit.hpp>

#ifdef NDN_CXX_HAVE_STACKTRACE
#include <boost/stacktrace/stacktrace.hpp>
#endif

#include <cstring>
#include <iostream>
#include <sstream>

namespace ndn {

BOOST_CONCEPT_ASSERT((boost::EqualityComparable<Interest>));
BOOST_CONCEPT_ASSERT((WireEncodable<Interest>));
BOOST_CONCEPT_ASSERT((WireEncodableWithEncodingBuffer<Interest>));
BOOST_CONCEPT_ASSERT((WireDecodable<Interest>));
static_assert(std::is_base_of<tlv::Error, Interest::Error>::value,
              "Interest::Error must inherit from tlv::Error");

#ifdef NDN_CXX_HAVE_TESTS
bool Interest::s_errorIfCanBePrefixUnset = true;
#endif // NDN_CXX_HAVE_TESTS
boost::logic::tribool Interest::s_defaultCanBePrefix = boost::logic::indeterminate;

Interest::Interest(const Name& name, time::milliseconds lifetime)
  : m_name(name)
  , m_isCanBePrefixSet(false)
  , m_interestLifetime(lifetime)
{
  if (lifetime < 0_ms) {
    NDN_THROW(std::invalid_argument("InterestLifetime must be >= 0"));
  }

  if (!boost::logic::indeterminate(s_defaultCanBePrefix)) {
    setCanBePrefix(bool(s_defaultCanBePrefix));
  }
}

Interest::Interest(const Block& wire)
  : m_isCanBePrefixSet(true)
{
  wireDecode(wire);
}

// ---- encode and decode ----

static void
warnOnceCanBePrefixUnset()
{
  static bool didWarn = false;
  if (!didWarn) {
    didWarn = true;
    std::cerr << "WARNING: Interest.CanBePrefix will be set to false in the near future. "
              << "Please declare a preferred setting via Interest::setDefaultCanBePrefix.\n";
#ifdef NDN_CXX_HAVE_STACKTRACE
    if (std::getenv("NDN_CXX_VERBOSE_CANBEPREFIX_UNSET_WARNING") != nullptr) {
      std::cerr << boost::stacktrace::stacktrace(2, 64);
    }
#endif
  }
}

template<encoding::Tag TAG>
size_t
Interest::wireEncode(EncodingImpl<TAG>& encoder) const
{
  if (!m_isCanBePrefixSet) {
    warnOnceCanBePrefixUnset();
#ifdef NDN_CXX_HAVE_TESTS
    if (s_errorIfCanBePrefixUnset) {
      NDN_THROW(std::logic_error("Interest.CanBePrefix is unset"));
    }
#endif // NDN_CXX_HAVE_TESTS
  }

  if (hasApplicationParameters()) {
    return encode03(encoder);
  }
  else {
    return encode02(encoder);
  }
}

template<encoding::Tag TAG>
size_t
Interest::encode02(EncodingImpl<TAG>& encoder) const
{
  size_t totalLength = 0;

  // Encode as NDN Packet Format v0.2
  // Interest ::= INTEREST-TYPE TLV-LENGTH
  //                Name
  //                Selectors?
  //                Nonce
  //                InterestLifetime?
  //                ForwardingHint?

  // (reverse encoding)

  // ForwardingHint
  if (getForwardingHint().size() > 0) {
    totalLength += getForwardingHint().wireEncode(encoder);
  }

  // InterestLifetime
  if (getInterestLifetime() != DEFAULT_INTEREST_LIFETIME) {
    totalLength += prependNonNegativeIntegerBlock(encoder, tlv::InterestLifetime,
                                                  static_cast<uint64_t>(getInterestLifetime().count()));
  }

  // Nonce
  uint32_t nonce = getNonce(); // if nonce was unset, getNonce generates a random nonce
  totalLength += encoder.prependByteArrayBlock(tlv::Nonce, reinterpret_cast<uint8_t*>(&nonce), sizeof(nonce));

  // Selectors
  if (hasSelectors()) {
    totalLength += getSelectors().wireEncode(encoder);
  }

  // Name
  totalLength += getName().wireEncode(encoder);

  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::Interest);
  return totalLength;
}

template<encoding::Tag TAG>
size_t
Interest::encode03(EncodingImpl<TAG>& encoder) const
{
  size_t totalLength = 0;

  // Encode as NDN Packet Format v0.3
  // Interest ::= INTEREST-TYPE TLV-LENGTH
  //                Name
  //                CanBePrefix?
  //                MustBeFresh?
  //                ForwardingHint?
  //                Nonce?
  //                InterestLifetime?
  //                HopLimit?
  //                (ApplicationParameters |
  //                 ApplicationParameters InterestSignatureInfo InterestSignatureValue)?


  // (reverse encoding)

  if (hasSignature()) {
    if (!(*m_signature)) {
      NDN_THROW(Error("Requested Signed Interest wire format, signature invalid"));
    }

    if (!hasApplicationParameters()) {
      NDN_THROW(Error("Requested Signed Interest wire format, no Application Parameters"));
    }

    // SignatureValue
    totalLength += encoder.prependBlock(m_signature->getValue());

    // SignatureInfo
    totalLength += encoder.prependBlock(m_signature->getInfo());
  }

  // ApplicationParameters
  if (hasApplicationParameters()) {
    totalLength += encoder.prependBlock(getApplicationParameters());
  }

  // HopLimit: not yet supported

  // InterestLifetime
  if (getInterestLifetime() != DEFAULT_INTEREST_LIFETIME) {
    totalLength += prependNonNegativeIntegerBlock(encoder, tlv::InterestLifetime,
                                                  static_cast<uint64_t>(getInterestLifetime().count()));
  }

  // Nonce
  uint32_t nonce = getNonce(); // if nonce was unset, getNonce generates a random nonce
  totalLength += encoder.prependByteArrayBlock(tlv::Nonce, reinterpret_cast<uint8_t*>(&nonce), sizeof(nonce));

  // ForwardingHint
  if (!getForwardingHint().empty()) {
    totalLength += getForwardingHint().wireEncode(encoder);
  }

  // MustBeFresh
  if (getMustBeFresh()) {
    totalLength += prependEmptyBlock(encoder, tlv::MustBeFresh);
  }

  // CanBePrefix
  if (getCanBePrefix()) {
    totalLength += prependEmptyBlock(encoder, tlv::CanBePrefix);
  }

  // Name
  totalLength += getName().wireEncode(encoder);

  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::Interest);
  return totalLength;
}

NDN_CXX_DEFINE_WIRE_ENCODE_INSTANTIATIONS(Interest);

const Block&
Interest::wireEncode() const
{
  if (m_wire.hasWire())
    return m_wire;

  EncodingEstimator estimator;
  size_t estimatedSize = wireEncode(estimator);

  EncodingBuffer buffer(estimatedSize, 0);
  wireEncode(buffer);

  const_cast<Interest*>(this)->wireDecode(buffer.block());
  return m_wire;
}

void
Interest::wireDecode(const Block& wire)
{
  m_wire = wire;
  m_wire.parse();

  if (m_wire.type() != tlv::Interest) {
    NDN_THROW(Error("Interest", m_wire.type()));
  }

  if (!decode02()) {
    decode03();
    if (!hasNonce()) {
      setNonce(getNonce());
    }
  }

  m_isCanBePrefixSet = true; // don't trigger warning from decoded packet
}

bool
Interest::decode02()
{
  auto element = m_wire.elements_begin();

  // Name
  if (element != m_wire.elements_end() && element->type() == tlv::Name) {
    m_name.wireDecode(*element);
    ++element;
  }
  else {
    return false;
  }

  // Selectors?
  if (element != m_wire.elements_end() && element->type() == tlv::Selectors) {
    m_selectors.wireDecode(*element);
    ++element;
  }
  else {
    m_selectors = {};
  }

  // Nonce
  if (element != m_wire.elements_end() && element->type() == tlv::Nonce) {
    uint32_t nonce = 0;
    if (element->value_size() != sizeof(nonce)) {
      NDN_THROW(Error("Nonce element is malformed"));
    }
    std::memcpy(&nonce, element->value(), sizeof(nonce));
    m_nonce = nonce;
    ++element;
  }
  else {
    return false;
  }

  // InterestLifetime?
  if (element != m_wire.elements_end() && element->type() == tlv::InterestLifetime) {
    m_interestLifetime = time::milliseconds(readNonNegativeInteger(*element));
    ++element;
  }
  else {
    m_interestLifetime = DEFAULT_INTEREST_LIFETIME;
  }

  // ForwardingHint?
  if (element != m_wire.elements_end() && element->type() == tlv::ForwardingHint) {
    m_forwardingHint.wireDecode(*element, false);
    ++element;
  }
  else {
    m_forwardingHint = {};
  }

  return element == m_wire.elements_end();
}

void
Interest::decode03()
{
  // Interest ::= INTEREST-TYPE TLV-LENGTH
  //                Name
  //                CanBePrefix?
  //                MustBeFresh?
  //                ForwardingHint?
  //                Nonce?
  //                InterestLifetime?
  //                HopLimit?
  //                (ApplicationParameters |
  //                 ApplicationParameters InterestSignatureInfo InterestSignatureValue)?

  auto element = m_wire.elements_begin();
  if (element == m_wire.elements_end() || element->type() != tlv::Name) {
    NDN_THROW(Error("Name element is missing or out of order"));
  }
  m_name.wireDecode(*element);
  if (m_name.empty()) {
    NDN_THROW(Error("Name has zero name components"));
  }
  int lastElement = 1; // last recognized element index, in spec order

  m_selectors = Selectors().setMaxSuffixComponents(1); // CanBePrefix=0
  m_nonce.reset();
  m_interestLifetime = DEFAULT_INTEREST_LIFETIME;
  m_forwardingHint = {};
  m_parameters = {};

  for (++element; element != m_wire.elements_end(); ++element) {
    switch (element->type()) {
      case tlv::CanBePrefix: {
        if (lastElement >= 2) {
          NDN_THROW(Error("CanBePrefix element is out of order"));
        }
        if (element->value_size() != 0) {
          NDN_THROW(Error("CanBePrefix element has non-zero TLV-LENGTH"));
        }
        m_selectors.setMaxSuffixComponents(-1);
        lastElement = 2;
        break;
      }
      case tlv::MustBeFresh: {
        if (lastElement >= 3) {
          NDN_THROW(Error("MustBeFresh element is out of order"));
        }
        if (element->value_size() != 0) {
          NDN_THROW(Error("MustBeFresh element has non-zero TLV-LENGTH"));
        }
        m_selectors.setMustBeFresh(true);
        lastElement = 3;
        break;
      }
      case tlv::ForwardingHint: {
        if (lastElement >= 4) {
          NDN_THROW(Error("ForwardingHint element is out of order"));
        }
        m_forwardingHint.wireDecode(*element);
        lastElement = 4;
        break;
      }
      case tlv::Nonce: {
        if (lastElement >= 5) {
          NDN_THROW(Error("Nonce element is out of order"));
        }
        uint32_t nonce = 0;
        if (element->value_size() != sizeof(nonce)) {
          NDN_THROW(Error("Nonce element is malformed"));
        }
        std::memcpy(&nonce, element->value(), sizeof(nonce));
        m_nonce = nonce;
        lastElement = 5;
        break;
      }
      case tlv::InterestLifetime: {
        if (lastElement >= 6) {
          NDN_THROW(Error("InterestLifetime element is out of order"));
        }
        m_interestLifetime = time::milliseconds(readNonNegativeInteger(*element));
        lastElement = 6;
        break;
      }
      case tlv::HopLimit: {
        if (lastElement >= 7) {
          break; // HopLimit is non-critical, ignore out-of-order appearance
        }
        if (element->value_size() != 1) {
          NDN_THROW(Error("HopLimit element is malformed"));
        }
        // TLV-VALUE is ignored
        lastElement = 7;
        break;
      }
      case tlv::ApplicationParameters: {
        if (lastElement >= 8) {
          break; // ApplicationParameters is non-critical, ignore out-of-order appearance
        }
        m_parameters = *element;
        lastElement = 8;
        break;
      }
      case tlv::InterestSignatureInfo: {
        if (lastElement >= 9) {
          break; // InterestSignatureInfo is non-critical, ignore out-of-order appearance
        }
        if (!hasApplicationParameters()) {
          NDN_THROW(Error("InterestSignatureInfo must be preceeded by App Params"));
        }
        if (!hasSignature()) {
            m_signature = Signature();
        }
        m_signature->setInfo(*element);
        if (!m_signature->getSignatureInfo().isInterestSignatureInfo()) {
          NDN_THROW(Error("SignatureInfo cannot sign Interest"));
        }
        lastElement = 9;
        break;
      }
      case tlv::InterestSignatureValue: {
        if (lastElement >= 10) {
          break; // InterestSignatureValue is non-critical, ignore out-of-order appearance
        }
        if (!hasSignature()) {
          NDN_THROW(Error("InterestSignatureValue must be preceeded by InterestSignatureInfo"));
        }
        m_signature->setValue(*element);
        lastElement = 10;
        break;
      }
      default: {
        if (tlv::isCriticalType(element->type())) {
          NDN_THROW(Error("Unrecognized element of critical type " + to_string(element->type())));
        }
        break;
      }
    }
  }
}

std::string
Interest::toUri() const
{
  std::ostringstream os;
  os << *this;
  return os.str();
}

// ---- matching ----

bool
Interest::matchesName(const Name& name) const
{
  if (name.size() < m_name.size())
    return false;

  if (!m_name.isPrefixOf(name))
    return false;

  if (getMinSuffixComponents() >= 0 &&
      // name must include implicit digest
      !(name.size() - m_name.size() >= static_cast<size_t>(getMinSuffixComponents())))
    return false;

  if (getMaxSuffixComponents() >= 0 &&
      // name must include implicit digest
      !(name.size() - m_name.size() <= static_cast<size_t>(getMaxSuffixComponents())))
    return false;

  if (!getExclude().empty() &&
      name.size() > m_name.size() &&
      getExclude().isExcluded(name[m_name.size()]))
    return false;

  return true;
}

bool
Interest::matchesData(const Data& data) const
{
  size_t interestNameLength = m_name.size();
  const Name& dataName = data.getName();
  size_t fullNameLength = dataName.size() + 1;

  // check Name and CanBePrefix
  if (interestNameLength == fullNameLength) {
    if (m_name.get(-1).isImplicitSha256Digest()) {
      if (m_name != data.getFullName()) {
        return false;
      }
    }
    else {
      // Interest Name is same length as Data full Name, but last component isn't digest
      // so there's no possibility of matching
      return false;
    }
  }
  else if (getCanBePrefix() ? !m_name.isPrefixOf(dataName) : (m_name != dataName)) {
    return false;
  }

  // check MustBeFresh
  if (getMustBeFresh() && data.getFreshnessPeriod() <= 0_ms) {
    return false;
  }

  return true;
}

bool
Interest::matchesInterest(const Interest& other) const
{
  return getName() == other.getName() &&
         getCanBePrefix() == other.getCanBePrefix() &&
         getMustBeFresh() == other.getMustBeFresh();
}

// ---- field accessors ----

uint32_t
Interest::getNonce() const
{
  if (!m_nonce) {
    m_nonce = random::generateWord32();
  }
  return *m_nonce;
}

Interest&
Interest::setNonce(uint32_t nonce)
{
  m_nonce = nonce;
  m_wire.reset();
  return *this;
}

void
Interest::refreshNonce()
{
  if (!hasNonce())
    return;

  uint32_t oldNonce = getNonce();
  uint32_t newNonce = oldNonce;
  while (newNonce == oldNonce)
    newNonce = random::generateWord32();

  setNonce(newNonce);
}

Interest&
Interest::setInterestLifetime(time::milliseconds lifetime)
{
  if (lifetime < 0_ms) {
    NDN_THROW(std::invalid_argument("InterestLifetime must be >= 0"));
  }
  m_interestLifetime = lifetime;
  m_wire.reset();
  return *this;
}

Interest&
Interest::setForwardingHint(const DelegationList& value)
{
  m_forwardingHint = value;
  m_wire.reset();
  return *this;
}

Interest&
Interest::setApplicationParameters(const Block& parameters)
{
  if (parameters.empty()) {
    m_parameters = Block(tlv::ApplicationParameters);
  }
  else if (parameters.type() == tlv::ApplicationParameters) {
    m_parameters = parameters;
  }
  else {
    m_parameters = Block(tlv::ApplicationParameters, parameters);
  }
  m_sign_wire.reset();
  m_wire.reset();
  return *this;
}

Interest&
Interest::setApplicationParameters(const uint8_t* buffer, size_t bufferSize)
{
  if (buffer == nullptr && bufferSize != 0) {
    NDN_THROW(std::invalid_argument("ApplicationParameters buffer cannot be nullptr"));
  }
  m_parameters = makeBinaryBlock(tlv::ApplicationParameters, buffer, bufferSize);
  m_sign_wire.reset();
  m_wire.reset();
  return *this;
}

Interest&
Interest::setApplicationParameters(ConstBufferPtr buffer)
{
  if (buffer == nullptr) {
    NDN_THROW(std::invalid_argument("ApplicationParameters buffer cannot be nullptr"));
  }
  m_parameters = Block(tlv::ApplicationParameters, std::move(buffer));
  m_sign_wire.reset();
  m_wire.reset();
  return *this;
}

Interest&
Interest::unsetApplicationParameters()
{
  m_parameters = {};
  m_sign_wire.reset();
  m_wire.reset();
  return *this;
}

// ---- signature utilities ----
//

const Signature&
Interest::getSignature() const
{
  if (!hasSignature()) {
    NDN_THROW(Error("Interest has no Signature"));
  }
  return *m_signature;
}

Interest&
Interest::setSignature(const Signature& signature)
{
  if (!signature.getSignatureInfo().isInterestSignatureInfo()) {
    NDN_THROW(Error("SignatureInfo cannot sign Interest"));
  }

  m_sign_wire.reset();
  m_wire.reset();

  if (m_parameters.empty()) {
    m_parameters = Block(tlv::ApplicationParameters);
  }

  m_signature = signature;
  return *this;
}

Interest&
Interest::setSignatureValue(const Block& value)
{
  m_wire.reset();
  m_signature->setValue(value);
  return *this;
}

ConstBufferPtr
Interest::wireEncodeParametersSuffix() const
{
  EncodingBuffer encoder;

  bool encodeParams = hasApplicationParameters();
  bool encodeSignature = encodeParams && hasSignature();

  if (encodeSignature) {
    encoder.prependBlock(m_signature->getValue());
    encoder.prependBlock(m_signature->getInfo());
  }

  if (encodeParams) {
    encoder.prependBlock(getApplicationParameters());
  }

  return encoder.getBuffer();
}

ConstBufferPtr
Interest::wireEncodeSignable() const
{
  if (m_sign_wire != nullptr)
    return m_sign_wire;

  EncodingBuffer encoder;

  if (!hasSignature()) {
    NDN_THROW(Error("Requested Signed Interest wire format for unsigned Interest"));
  }

  if (!getSignature()) {
    NDN_THROW(Error("Requested Signed Interest wire format, signature invalid"));
  }

  if (!hasApplicationParameters()) {
    NDN_THROW(Error("Requested Signed Interest wire format, no Application Parameters"));
  }

  encoder.prependBlock(m_signature->getInfo());
  encoder.prependBlock(getApplicationParameters());

  for (auto& component: m_name) {
    if (!component.isParametersSha256Digest()) {
      encoder.prependBlock(component);
    }
  }

  m_sign_wire = encoder.getBuffer();

  return m_sign_wire;
}

Interest&
Interest::recomputeParametersDigest()
{
  Name old_name(m_name);
  m_name.clear();

  for (auto& c: old_name) {
    if (!c.isParametersSha256Digest()) {
      m_name.append(c);
    }
  }

  ConstBufferPtr suffix = wireEncodeParametersSuffix();
  ConstBufferPtr digest = util::Sha256::computeDigest(suffix->get<uint8_t>(), suffix->size());

  m_name.appendParametersSha256Digest(digest);

  m_sign_wire.reset();
  m_wire.reset();
  return *this;
}

// ---- operators ----

bool
operator==(const Interest& lhs, const Interest& rhs)
{
  bool wasCanBePrefixSetOnLhs = lhs.m_isCanBePrefixSet;
  bool wasCanBePrefixSetOnRhs = rhs.m_isCanBePrefixSet;
  lhs.m_isCanBePrefixSet = true;
  rhs.m_isCanBePrefixSet = true;
  BOOST_SCOPE_EXIT_ALL(&) {
    lhs.m_isCanBePrefixSet = wasCanBePrefixSetOnLhs;
    rhs.m_isCanBePrefixSet = wasCanBePrefixSetOnRhs;
  };

  return lhs.wireEncode() == rhs.wireEncode();
}

std::ostream&
operator<<(std::ostream& os, const Interest& interest)
{
  os << interest.getName();

  char delim = '?';

  if (interest.getMinSuffixComponents() >= 0) {
    os << delim << "ndn.MinSuffixComponents=" << interest.getMinSuffixComponents();
    delim = '&';
  }
  if (interest.getMaxSuffixComponents() >= 0) {
    os << delim << "ndn.MaxSuffixComponents=" << interest.getMaxSuffixComponents();
    delim = '&';
  }
  if (interest.getChildSelector() != DEFAULT_CHILD_SELECTOR) {
    os << delim << "ndn.ChildSelector=" << interest.getChildSelector();
    delim = '&';
  }
  if (interest.getMustBeFresh()) {
    os << delim << "ndn.MustBeFresh=" << interest.getMustBeFresh();
    delim = '&';
  }
  if (interest.getInterestLifetime() != DEFAULT_INTEREST_LIFETIME) {
    os << delim << "ndn.InterestLifetime=" << interest.getInterestLifetime().count();
    delim = '&';
  }
  if (interest.hasNonce()) {
    os << delim << "ndn.Nonce=" << interest.getNonce();
    delim = '&';
  }
  if (!interest.getExclude().empty()) {
    os << delim << "ndn.Exclude=" << interest.getExclude();
    delim = '&';
  }
  if (interest.hasSignature()) {
    os << delim << "ndn.Signature=(type: " << interest.getSignature().getType()
       << ", value_length: " << interest.getSignature().getValue().value_size() << ")";
    delim = '&';
  }

  return os;
}

} // namespace ndn
