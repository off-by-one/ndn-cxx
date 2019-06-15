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
#include "ndn-cxx/util/random.hpp"

namespace ndn {
namespace security {

CommandInterestSigner::CommandInterestSigner(KeyChain& keyChain)
  : m_keyChain(keyChain)
{
}

Interest
CommandInterestSigner::makeCommandInterest(const Name& name, const SigningInfo& params)
{
  Interest commandInterest(name);
  commandInterest.setCanBePrefix(false);

  if (!(params.generateTimestamp() && params.generateNonce())) {
    SigningInfo newParams = params;
    newParams.setGenerateTimestamp();
    newParams.setGenerateNonce();
    m_keyChain.sign(commandInterest, newParams);
  }
  else {
    m_keyChain.sign(commandInterest, params);
  }

  return commandInterest;
}

} // namespace security
} // namespace ndn
