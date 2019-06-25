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

#include "ndn-cxx/signature.hpp"
#include "ndn-cxx/security/digest-sha256.hpp"
#include "ndn-cxx/security/signature-sha256-with-rsa.hpp"

#include "tests/boost-test.hpp"

namespace ndn {
namespace tests {

BOOST_AUTO_TEST_SUITE(TestSignature)

BOOST_AUTO_TEST_CASE(Equality)
{
  Signature a;
  Signature b;

  BOOST_CHECK_EQUAL(a == b, true);
  BOOST_CHECK_EQUAL(a != b, false);

  a = SignatureSha256WithRsa();
  BOOST_CHECK_EQUAL(a == b, false);
  BOOST_CHECK_EQUAL(a != b, true);

  b = SignatureSha256WithRsa();
  static const uint8_t someData[256] = {};
  Block signatureValue = makeBinaryBlock(tlv::SignatureValue, someData, sizeof(someData));
  b.setValue(signatureValue);
  BOOST_CHECK_EQUAL(a == b, false);
  BOOST_CHECK_EQUAL(a != b, true);

  a.setValue(signatureValue);
  BOOST_CHECK_EQUAL(a == b, true);
  BOOST_CHECK_EQUAL(a != b, false);

  a = DigestSha256();
  b = SignatureSha256WithRsa();
  BOOST_CHECK_EQUAL(a == b, false);
  BOOST_CHECK_EQUAL(a != b, true);

  b = DigestSha256();
  BOOST_CHECK_EQUAL(a == b, true);
  BOOST_CHECK_EQUAL(a != b, false);
}

BOOST_AUTO_TEST_CASE(IncorrectSignatureType)
{
  static const uint8_t interestSig[256] = {};
  static const uint8_t dataSig[256] = {};
  Block interestSigValue = makeBinaryBlock(tlv::InterestSignatureValue, interestSig, sizeof(interestSig));
  Block dataSigValue = makeBinaryBlock(tlv::SignatureValue, dataSig, sizeof(dataSig));

  SignatureInfo dataInfo;
  SignatureInfo interestInfo;
  interestInfo.setInfoType(tlv::InterestSignatureInfo);

  Signature a(dataInfo);
  BOOST_CHECK_THROW(a.setValue(interestSigValue), Signature::Error);
  BOOST_CHECK_NO_THROW(a.setValue(dataSigValue));

  Signature b(interestInfo);
  BOOST_CHECK_THROW(b.setValue(dataSigValue), Signature::Error);
  BOOST_CHECK_NO_THROW(b.setValue(interestSigValue));
}

BOOST_AUTO_TEST_SUITE_END() // TestSignature

} // namespace tests
} // namespace ndn
