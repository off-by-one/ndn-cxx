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

#include "ndn-cxx/signature.hpp"

namespace ndn {

BOOST_CONCEPT_ASSERT((boost::EqualityComparable<InterestSignature>));
static_assert(std::is_base_of<tlv::Error, InterestSignature::Error>::value,
              "InterestSignature::Error must inherit from tlv::Error");

template<>
InterestSignature::SignatureProto(const Block& info, const Block& value)
  : m_info(info)
  , m_value(value)
{
}


template<>
InterestSignature::SignatureProto(const InterestSignatureInfo& info, const Block& value)
  : m_info(info)
  , m_value(value)
{
}

template<>
tlv::SignatureTypeValue
InterestSignature::getType() const
{
  if (!*this) {
    NDN_THROW(Error("InterestSignature is invalid"));
  }
  return static_cast<tlv::SignatureTypeValue>(m_info.getSignatureType());
}

template<>
void
InterestSignature::setInfo(const Block& info)
{
  m_info = InterestSignatureInfo(info);
}

template<>
void
InterestSignature::setValue(const Block& value)
{
  if (value.type() != tlv::InterestSignatureValue) {
    NDN_THROW(Error("InterestSignatureValue", value.type()));
  }
  m_value = value;
}

bool
operator==(const InterestSignature& lhs, const InterestSignature& rhs)
{
  return lhs.getSignatureInfo() == rhs.getSignatureInfo() && lhs.getValue() == rhs.getValue();
}

} // namespace ndn
