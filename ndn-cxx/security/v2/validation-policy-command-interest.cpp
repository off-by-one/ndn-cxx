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

#include "ndn-cxx/security/v2/validation-policy-command-interest.hpp"
#include "ndn-cxx/security/v2/validation-policy-signed-interest.hpp"

namespace ndn {
namespace security {
namespace v2 {

ValidationPolicyCommandInterest::ValidationPolicyCommandInterest(unique_ptr<ValidationPolicy> inner,
                                                                 const Options& options)
{
  if (inner == nullptr) {
    NDN_THROW(std::invalid_argument("inner policy is missing"));
  }

  ValidationPolicySignedInterest::Options inner_options(true, true, false);

  inner_options.gracePeriod = std::max(options.gracePeriod, 0_ns);
  inner_options.maxTimestampRecords = options.maxRecords;
  inner_options.timestampRecordLifetime = options.recordLifetime;

  setInnerPolicy(make_unique<ValidationPolicySignedInterest>(std::move(inner), inner_options));
}

void
ValidationPolicyCommandInterest::checkPolicy(const Data& data, const shared_ptr<ValidationState>& state,
                                             const ValidationContinuation& continueValidation)
{
  getInnerPolicy().checkPolicy(data, state, continueValidation);
}

void
ValidationPolicyCommandInterest::checkPolicy(const Interest& interest, const shared_ptr<ValidationState>& state,
                                             const ValidationContinuation& continueValidation)
{
  getInnerPolicy().checkPolicy(interest, state, continueValidation);
}

} // namespace v2
} // namespace security
} // namespace ndn
