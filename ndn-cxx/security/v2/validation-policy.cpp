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

#include "ndn-cxx/security/v2/validation-policy.hpp"
#include "ndn-cxx/security/signing-info.hpp"

namespace ndn {
namespace security {
namespace v2 {

void
ValidationPolicy::setInnerPolicy(unique_ptr<ValidationPolicy> innerPolicy)
{
  if (innerPolicy == nullptr) {
    NDN_THROW(std::invalid_argument("Inner policy argument cannot be nullptr"));
  }

  if (m_validator != nullptr) {
    innerPolicy->setValidator(*m_validator);
  }

  if (m_innerPolicy == nullptr) {
    m_innerPolicy = std::move(innerPolicy);
  }
  else {
    m_innerPolicy->setInnerPolicy(std::move(innerPolicy));
  }
}

ValidationPolicy&
ValidationPolicy::getInnerPolicy()
{
  return *m_innerPolicy;
}

void
ValidationPolicy::setValidator(Validator& validator)
{
  m_validator = &validator;
  if (m_innerPolicy != nullptr) {
    m_innerPolicy->setValidator(validator);
  }
}

static Name
getKeyLocatorName(const SignatureInfo& si, ValidationState& state)
{
  if (si.getSignatureType() == tlv::DigestSha256) {
    return SigningInfo::getDigestSha256Identity();
  }

  if (!si.hasKeyLocator()) {
    state.fail({ValidationError::Code::INVALID_KEY_LOCATOR, "KeyLocator is missing"});
    return Name();
  }

  const KeyLocator& kl = si.getKeyLocator();
  if (kl.getType() != KeyLocator::KeyLocator_Name) {
    state.fail({ValidationError::Code::INVALID_KEY_LOCATOR, "KeyLocator type is not Name"});
    return Name();
  }

  return kl.getName();
}

Name
getKeyLocatorName(const Data& data, ValidationState& state)
{
  return getKeyLocatorName(data.getSignature().getSignatureInfo(), state);
}

Name
getKeyLocatorName(const Interest& interest, ValidationState& state)
{
  return getKeyLocatorName(interest.getSignature().getSignatureInfo(), state);
}

} // namespace v2
} // namespace security
} // namespace ndn
