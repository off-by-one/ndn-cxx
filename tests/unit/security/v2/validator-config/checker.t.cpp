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

#include "ndn-cxx/security/v2/validator-config/checker.hpp"
#include "ndn-cxx/security/command-interest-signer.hpp"
#include "ndn-cxx/security/v2/validation-policy.hpp"
#include "ndn-cxx/security/v2/validation-state.hpp"
#include "ndn-cxx/security/v2/validation-callback.hpp"

#include "tests/boost-test.hpp"
#include "tests/unit/security/v2/validator-fixture.hpp"
#include "tests/unit/security/v2/validator-config/common.hpp"

namespace ndn {
namespace security {
namespace v2 {
namespace validator_config {
namespace tests {

using namespace ndn::tests;

BOOST_AUTO_TEST_SUITE(Security)
BOOST_AUTO_TEST_SUITE(V2)
BOOST_AUTO_TEST_SUITE(ValidatorConfig)

class CheckerFixture : public IdentityManagementFixture
{
public:
  CheckerFixture()
  {
    names.push_back("/foo/bar");
    names.push_back("/foo/bar/bar");
    names.push_back("/foo");
    names.push_back("/other/prefix");
  }

  static Name
  makeSignedInterestName(const Name& name)
  {
    return Name(name).append("Digest");
  }

  static Name
  makeKeyLocatorName(const Name& name)
  {
    return Name(name).append("KEY").append("v=1");
  }

public:
  std::vector<Name> names;
};

BOOST_FIXTURE_TEST_SUITE(TestChecker, CheckerFixture)

class NameRelationEqual : public CheckerFixture
{
public:
  NameRelationEqual()
    : checker("/foo/bar", NameRelation::EQUAL)
  {
  }

public:
  NameRelationChecker checker;
  std::vector<std::vector<bool>> outcomes = {{true, false, false, false},
                                             {true, false, false, false},
                                             {true, false, false, false},
                                             {true, false, false, false}};
};

class NameRelationIsPrefixOf : public CheckerFixture
{
public:
  NameRelationIsPrefixOf()
    : checker("/foo/bar", NameRelation::IS_PREFIX_OF)
  {
  }

public:
  NameRelationChecker checker;
  std::vector<std::vector<bool>> outcomes = {{true, true, false, false},
                                             {true, true, false, false},
                                             {true, true, false, false},
                                             {true, true, false, false}};
};

class NameRelationIsStrictPrefixOf : public CheckerFixture
{
public:
  NameRelationIsStrictPrefixOf()
    : checker("/foo/bar", NameRelation::IS_STRICT_PREFIX_OF)
  {
  }

public:
  NameRelationChecker checker;
  std::vector<std::vector<bool>> outcomes = {{false, true, false, false},
                                             {false, true, false, false},
                                             {false, true, false, false},
                                             {false, true, false, false}};
};

class RegexEqual : public CheckerFixture
{
public:
  RegexEqual()
    : checker(Regex("^<foo><bar><KEY><>$"))
  {
  }

public:
  RegexChecker checker;
  std::vector<std::vector<bool>> outcomes = {{true, false, false, false},
                                             {true, false, false, false},
                                             {true, false, false, false},
                                             {true, false, false, false}};
};

class RegexIsPrefixOf : public CheckerFixture
{
public:
  RegexIsPrefixOf()
    : checker(Regex("^<foo><bar><>*<KEY><>$"))
  {
  }

public:
  RegexChecker checker;
  std::vector<std::vector<bool>> outcomes = {{true, true, false, false},
                                             {true, true, false, false},
                                             {true, true, false, false},
                                             {true, true, false, false}};
};

class RegexIsStrictPrefixOf : public CheckerFixture
{
public:
  RegexIsStrictPrefixOf()
    : checker(Regex("^<foo><bar><>+<KEY><>$"))
  {
  }

public:
  RegexChecker checker;
  std::vector<std::vector<bool>> outcomes = {{false, true, false, false},
                                             {false, true, false, false},
                                             {false, true, false, false},
                                             {false, true, false, false}};
};

class HyperRelationEqual : public CheckerFixture
{
public:
  HyperRelationEqual()
    : checker("^(<>+)$", "\\1", "^(<>+)<KEY><>$", "\\1", NameRelation::EQUAL)
  {
  }

public:
  HyperRelationChecker checker;
  std::vector<std::vector<bool>> outcomes = {{true,  false, false, false},
                                             {false, true,  false, false},
                                             {false, false, true,  false},
                                             {false, false, false, true}};
};

class HyperRelationIsPrefixOf : public CheckerFixture
{
public:
  HyperRelationIsPrefixOf()
    : checker("^(<>+)$", "\\1", "^(<>+)<KEY><>$", "\\1", NameRelation::IS_PREFIX_OF)
  {
  }

public:
  HyperRelationChecker checker;
  std::vector<std::vector<bool>> outcomes = {{true,  false, true,  false},
                                             {true,  true,  true,  false},
                                             {false, false, true,  false},
                                             {false, false, false, true}};
};

class HyperRelationIsStrictPrefixOf : public CheckerFixture
{
public:
  HyperRelationIsStrictPrefixOf()
    : checker("^(<>+)$", "\\1", "^(<>+)<KEY><>$", "\\1", NameRelation::IS_STRICT_PREFIX_OF)
  {
  }

public:
  HyperRelationChecker checker;
  std::vector<std::vector<bool>> outcomes = {{false, false, true,  false},
                                             {true,  false, true,  false},
                                             {false, false, false, false},
                                             {false, false, false, false}};
};

class Hierarchical : public CheckerFixture
{
public:
  Hierarchical()
    : checkerPtr(Checker::create(makeSection(R"CONF(
          type hierarchical
          sig-type rsa-sha256
        )CONF"), "test-config"))
    , checker(*checkerPtr)
  {
  }

public:
  std::unique_ptr<Checker> checkerPtr;
  Checker& checker;

  std::vector<std::vector<bool>> outcomes = {{true,  false, true,  false},
                                             {true,  true,  true,  false},
                                             {false, false, true,  false},
                                             {false, false, false, true}};
};

class CustomizedNameRelation : public CheckerFixture
{
public:
  CustomizedNameRelation()
    : checkerPtr(Checker::create(makeSection(R"CONF(
          type customized
          sig-type rsa-sha256
          key-locator
          {
            type name
            name /foo/bar
            relation equal
          }
        )CONF"), "test-config"))
    , checker(*checkerPtr)
  {
  }

public:
  std::unique_ptr<Checker> checkerPtr;
  Checker& checker;

  std::vector<std::vector<bool>> outcomes = {{true, false, false, false},
                                             {true, false, false, false},
                                             {true, false, false, false},
                                             {true, false, false, false}};
};

class CustomizedRegex : public CheckerFixture
{
public:
  CustomizedRegex()
    : checkerPtr(Checker::create(makeSection(R"CONF(
          type customized
          sig-type rsa-sha256
          key-locator
          {
            type name
            regex ^<foo><bar><KEY><>$
          }
        )CONF"), "test-config"))
    , checker(*checkerPtr)
  {
  }

public:
  std::unique_ptr<Checker> checkerPtr;
  Checker& checker;

  std::vector<std::vector<bool>> outcomes = {{true, false, false, false},
                                             {true, false, false, false},
                                             {true, false, false, false},
                                             {true, false, false, false}};
};

class CustomizedHyperRelation : public CheckerFixture
{
public:
  CustomizedHyperRelation()
    : checkerPtr(Checker::create(makeSection(R"CONF(
          type customized
          sig-type rsa-sha256
          key-locator
          {
            type name
            hyper-relation
            {
              k-regex ^(<>+)<KEY><>$
              k-expand \\1
              h-relation is-prefix-of
              p-regex ^(<>+)$
              p-expand \\1
            }
          }
        )CONF"), "test-config"))
    , checker(*checkerPtr)
  {
  }

public:
  std::unique_ptr<Checker> checkerPtr;
  Checker& checker;

  std::vector<std::vector<bool>> outcomes = {{true,  false, true,  false},
                                             {true,  true,  true,  false},
                                             {false, false, true,  false},
                                             {false, false, false, true}};
};

using Tests = boost::mpl::vector<NameRelationEqual, NameRelationIsPrefixOf, NameRelationIsStrictPrefixOf,
                                 RegexEqual, RegexIsPrefixOf, RegexIsStrictPrefixOf,
                                 HyperRelationEqual, HyperRelationIsPrefixOf, HyperRelationIsStrictPrefixOf,
                                 Hierarchical,
                                 CustomizedNameRelation, CustomizedRegex, CustomizedHyperRelation>;

BOOST_FIXTURE_TEST_CASE_TEMPLATE(Checks, T, Tests, T)
{
  using namespace ndn::security::v2::tests;

  BOOST_REQUIRE_EQUAL(this->outcomes.size(), this->names.size());
  for (size_t i = 0; i < this->names.size(); ++i) {
    BOOST_REQUIRE_EQUAL(this->outcomes[i].size(), this->names.size());
    for (size_t j = 0; j < this->names.size(); ++j) {
      const Name& pktName = this->names[i];
      Name klName = this->makeKeyLocatorName(this->names[j]);
      bool expectedOutcome = this->outcomes[i][j];

      auto dataState = make_shared<DummyValidationState>();
      BOOST_CHECK_EQUAL(this->checker.check(tlv::Data, pktName, klName, dataState), expectedOutcome);
      BOOST_CHECK_EQUAL(boost::logic::indeterminate(dataState->getOutcome()), expectedOutcome);
      BOOST_CHECK_EQUAL(bool(dataState->getOutcome()), false);

      auto interestState = make_shared<DummyValidationState>();
      BOOST_CHECK_EQUAL(this->checker.check(tlv::Interest, this->makeSignedInterestName(pktName),
                                            klName, interestState), expectedOutcome);
      BOOST_CHECK_EQUAL(boost::logic::indeterminate(interestState->getOutcome()), expectedOutcome);
      BOOST_CHECK_EQUAL(bool(interestState->getOutcome()), false);
    }
  }
}

class ReplayCheckerFixture : public IdentityManagementTimeFixture
{
public:
  ReplayCheckerFixture()
    : m_pktName("/foo/bar/Digest")
    , m_klName("/foo/bar/KEY")
    , m_klOtherName("/foo/other/KEY")
    , m_interest(m_pktName)
  {
    m_klName.append("v=1");
    m_klOtherName.append("v=1");
    m_sigInfo.setInfoType(tlv::InterestSignatureInfo);
  }

  shared_ptr<ndn::security::v2::tests::DummyInterestValidationState>
  makeFreshValidationState()
  {
    return make_shared<ndn::security::v2::tests::DummyInterestValidationState>(m_interest
        ,[&] (const Interest& i) {}
        ,[&] (const Interest &i, const security::v2::ValidationError& e) {});
  }

  bool
  runChecker(shared_ptr<Checker> checkerPtr, const Name& klName)
  {
    auto state = makeFreshValidationState();
    bool result = checkerPtr->check(tlv::Interest, m_pktName, klName, state);
    if (result) {
      state->performAfterSuccess();
    }
    return result;
  }

public:
  Name m_pktName;
  Name m_klName;
  Name m_klOtherName;

  SignatureInfo m_sigInfo;
  Interest m_interest;
};


BOOST_FIXTURE_TEST_CASE(TestNonceChecker, ReplayCheckerFixture)
{
  std::shared_ptr<Checker> checkerPtr = std::move(Checker::create(makeSection(R"CONF(
          type nonce
          max-records 1
          max-lifetime "1 ms"
        )CONF"), "test-config"));
  m_sigInfo.setNonce(4);
  m_interest.setSignature(Signature(m_sigInfo));
  BOOST_CHECK(runChecker(checkerPtr, m_klName));
  BOOST_CHECK(!runChecker(checkerPtr, m_klName));

  m_sigInfo.setNonce(5);
  m_interest.setSignature(Signature(m_sigInfo));
  BOOST_CHECK(runChecker(checkerPtr, m_klName));

  advanceClocks(10_ms);
  BOOST_CHECK(runChecker(checkerPtr, m_klName));
  BOOST_CHECK(runChecker(checkerPtr, m_klOtherName));

  checkerPtr = std::move(Checker::create(makeSection(R"CONF(
          type nonce
          max-records 2
          max-lifetime "1 ms"
        )CONF"), "test-config"));
  BOOST_CHECK(runChecker(checkerPtr, m_klName));
  BOOST_CHECK(runChecker(checkerPtr, m_klOtherName));
  BOOST_CHECK(!runChecker(checkerPtr, m_klName));
  BOOST_CHECK(!runChecker(checkerPtr, m_klOtherName));

  advanceClocks(10_ms);
  BOOST_CHECK(runChecker(checkerPtr, m_klName));
  BOOST_CHECK(runChecker(checkerPtr, m_klOtherName));
}

BOOST_FIXTURE_TEST_CASE(TestTimestampChecker, ReplayCheckerFixture)
{
  std::shared_ptr<Checker> checkerPtr = std::move(Checker::create(makeSection(R"CONF(
          type timestamp
          max-records 1
          max-lifetime "10 ms"
          grace-period "1 ms"
        )CONF"), "test-config"));
  m_sigInfo.setTimestamp();
  m_interest.setSignature(Signature(m_sigInfo));
  advanceClocks(2_ms);
  BOOST_CHECK(!runChecker(checkerPtr, m_klName));

  m_sigInfo.setTimestamp();
  m_interest.setSignature(Signature(m_sigInfo));
  BOOST_CHECK(runChecker(checkerPtr, m_klName));

  BOOST_CHECK(!runChecker(checkerPtr, m_klName));

  advanceClocks(1_ms);
  m_sigInfo.setTimestamp();
  m_interest.setSignature(Signature(m_sigInfo));

  BOOST_CHECK(runChecker(checkerPtr, m_klName));
  BOOST_CHECK(runChecker(checkerPtr, m_klOtherName));
  BOOST_CHECK(runChecker(checkerPtr, m_klName));

  checkerPtr = std::move(Checker::create(makeSection(R"CONF(
          type timestamp
          max-records 2
          max-lifetime "10 ms"
          grace-period "100 ms"
        )CONF"), "test-config"));
  m_sigInfo.setTimestamp();
  m_interest.setSignature(Signature(m_sigInfo));
  BOOST_CHECK(runChecker(checkerPtr, m_klName));
  BOOST_CHECK(runChecker(checkerPtr, m_klOtherName));
  BOOST_CHECK(!runChecker(checkerPtr, m_klName));
  BOOST_CHECK(!runChecker(checkerPtr, m_klOtherName));

  advanceClocks(10_ms);
  BOOST_CHECK(runChecker(checkerPtr, m_klName));
  BOOST_CHECK(runChecker(checkerPtr, m_klOtherName));
}

BOOST_FIXTURE_TEST_CASE(TestSeqNumChecker, ReplayCheckerFixture)
{
  std::shared_ptr<Checker> checkerPtr = std::move(Checker::create(makeSection(R"CONF(
          type seq-num
          max-records 1
          max-lifetime "10 ms"
          min-value 20
        )CONF"), "test-config"));
  m_sigInfo.setSequenceNumber(10);
  m_interest.setSignature(Signature(m_sigInfo));
  BOOST_CHECK(!runChecker(checkerPtr, m_klName));

  m_sigInfo.setSequenceNumber(20);
  m_interest.setSignature(Signature(m_sigInfo));
  BOOST_CHECK(runChecker(checkerPtr, m_klName));
  BOOST_CHECK(!runChecker(checkerPtr, m_klName));

  advanceClocks(10_ms);
  BOOST_CHECK(runChecker(checkerPtr, m_klName));
  BOOST_CHECK(runChecker(checkerPtr, m_klOtherName));
  BOOST_CHECK(runChecker(checkerPtr, m_klName));

  checkerPtr = std::move(Checker::create(makeSection(R"CONF(
          type seq-num
          max-records 2
          max-lifetime "10 ms"
        )CONF"), "test-config"));
  m_sigInfo.setSequenceNumber(0);
  m_interest.setSignature(Signature(m_sigInfo));
  BOOST_CHECK(runChecker(checkerPtr, m_klName));
  BOOST_CHECK(runChecker(checkerPtr, m_klOtherName));
  BOOST_CHECK(!runChecker(checkerPtr, m_klName));
  BOOST_CHECK(!runChecker(checkerPtr, m_klOtherName));

  advanceClocks(10_ms);
  BOOST_CHECK(runChecker(checkerPtr, m_klName));
  BOOST_CHECK(runChecker(checkerPtr, m_klOtherName));
}

BOOST_AUTO_TEST_SUITE_END() // TestChecker
BOOST_AUTO_TEST_SUITE_END() // ValidatorConfig
BOOST_AUTO_TEST_SUITE_END() // V2
BOOST_AUTO_TEST_SUITE_END() // Security

} // namespace tests
} // namespace validator_config
} // namespace v2
} // namespace security
} // namespace ndn
