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

#include "ndn-cxx/security/command-interest-signer.hpp"
#include "ndn-cxx/security/signing-helpers.hpp"

#include "tests/boost-test.hpp"
#include "tests/unit/identity-management-time-fixture.hpp"

namespace ndn {
namespace security {
namespace tests {

using namespace ndn::tests;

BOOST_AUTO_TEST_SUITE(Security)
BOOST_FIXTURE_TEST_SUITE(TestCommandInterestSigner, IdentityManagementTimeFixture)

BOOST_AUTO_TEST_CASE(Basic)
{
  addIdentity("/test");

  CommandInterestSigner signer(m_keyChain);
  Interest i1 = signer.makeCommandInterest("/hello/world");
  BOOST_CHECK_EQUAL(i1.getName().get(-1).isParametersSha256Digest(), true);
  BOOST_CHECK_EQUAL(i1.hasSignature(), true);

  uint64_t timestamp = toUnixTimestamp(time::system_clock::now()).count();
  BOOST_CHECK_EQUAL(i1.getSignature().getSignatureInfo().getTimestamp(), timestamp);

  Interest i2 = signer.makeCommandInterest("/hello/world/!", signingByIdentity("/test"));
  BOOST_CHECK_EQUAL(i2.getName().get(-1).isParametersSha256Digest(), true);
  BOOST_CHECK_EQUAL(i2.hasSignature(), true);
  BOOST_CHECK_GE(i2.getSignature().getSignatureInfo().getTimestamp(), i1.getSignature().getSignatureInfo().getTimestamp());

  advanceClocks(100_s);

  i2 = signer.makeCommandInterest("/hello/world/!");
  BOOST_CHECK_GT(i2.getSignature().getSignatureInfo().getTimestamp(), i1.getSignature().getSignatureInfo().getTimestamp());
}

BOOST_AUTO_TEST_SUITE_END() // TestCommandInterestSigner
BOOST_AUTO_TEST_SUITE_END() // Security

} // namespace tests
} // namespace security
} // namespace ndn
