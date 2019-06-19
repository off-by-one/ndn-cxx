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

#include "ndn-cxx/security/verification-helpers.hpp"

#include "ndn-cxx/data.hpp"
#include "ndn-cxx/interest.hpp"
#include "ndn-cxx/encoding/buffer-stream.hpp"
#include "ndn-cxx/security/impl/openssl.hpp"
#include "ndn-cxx/security/pib/key.hpp"
#include "ndn-cxx/security/transform/bool-sink.hpp"
#include "ndn-cxx/security/transform/buffer-source.hpp"
#include "ndn-cxx/security/transform/digest-filter.hpp"
#include "ndn-cxx/security/transform/public-key.hpp"
#include "ndn-cxx/security/transform/stream-sink.hpp"
#include "ndn-cxx/security/transform/verifier-filter.hpp"
#include "ndn-cxx/security/v2/certificate.hpp"

namespace ndn {
namespace security {

bool
verifySignature(const uint8_t* blob, size_t blobLen, const uint8_t* sig, size_t sigLen,
                const transform::PublicKey& key)
{
  bool result = false;
  try {
    using namespace transform;
    bufferSource(blob, blobLen) >> verifierFilter(DigestAlgorithm::SHA256, key, sig, sigLen)
                                >> boolSink(result);
  }
  catch (const transform::Error&) {
    return false;
  }
  return result;
}

bool
verifySignature(const uint8_t* data, size_t dataLen, const uint8_t* sig, size_t sigLen,
                const uint8_t* key, size_t keyLen)
{
  transform::PublicKey pKey;
  try {
    pKey.loadPkcs8(key, keyLen);
  }
  catch (const transform::Error&) {
    return false;
  }

  return verifySignature(data, dataLen, sig, sigLen, pKey);
}

static std::tuple<bool, const uint8_t*, size_t, const uint8_t*, size_t>
parse(const Data& data)
{
  try {
    return std::make_tuple(true,
                           data.wireEncode().value(),
                           data.wireEncode().value_size() - data.getSignature().getValue().size(),
                           data.getSignature().getValue().value(),
                           data.getSignature().getValue().value_size());
  }
  catch (const tlv::Error&) {
    return std::make_tuple(false, nullptr, 0, nullptr, 0);
  }
}

static std::tuple<bool, const uint8_t*, size_t, const uint8_t*, size_t>
parse(const Interest& interest)
{
  try {
    return std::make_tuple(true,
                           interest.wireEncodeSignable()->get<uint8_t>(),
                           interest.wireEncodeSignable()->size(),
                           interest.getSignature().getValue().value(),
                           interest.getSignature().getValue().value_size());
  }
  catch (const tlv::Error&) {
    return std::make_tuple(false, nullptr, 0, nullptr, 0);
  }
}

static bool
verifySignature(const std::tuple<bool, const uint8_t*, size_t, const uint8_t*, size_t>& params,
                const transform::PublicKey& key)
{
  bool isParsable = false;
  const uint8_t* buf = nullptr;
  size_t bufLen = 0;
  const uint8_t* sig = nullptr;
  size_t sigLen = 0;

  std::tie(isParsable, buf, bufLen, sig, sigLen) = params;

  if (isParsable)
    return verifySignature(buf, bufLen, sig, sigLen, key);
  else
    return false;
}

static bool
verifySignature(const std::tuple<bool, const uint8_t*, size_t, const uint8_t*, size_t>& params,
                const uint8_t* key, size_t keyLen)
{
  bool isParsable = false;
  const uint8_t* buf = nullptr;
  size_t bufLen = 0;
  const uint8_t* sig = nullptr;
  size_t sigLen = 0;

  std::tie(isParsable, buf, bufLen, sig, sigLen) = params;

  if (isParsable)
    return verifySignature(buf, bufLen, sig, sigLen, key, keyLen);
  else
    return false;
}

bool
verifySignature(const Data& data, const transform::PublicKey& key)
{
  return verifySignature(parse(data), key);
}

bool
verifySignature(const Interest& interest, const transform::PublicKey& key)
{
  return verifySignature(parse(interest), key);
}

bool
verifySignature(const Data& data, const pib::Key& key)
{
  return verifySignature(parse(data), key.getPublicKey().data(), key.getPublicKey().size());
}

bool
verifySignature(const Interest& interest, const pib::Key& key)
{
  return verifySignature(parse(interest), key.getPublicKey().data(), key.getPublicKey().size());
}

bool
verifySignature(const Data& data, const uint8_t* key, size_t keyLen)
{
  return verifySignature(parse(data), key, keyLen);
}

bool
verifySignature(const Interest& interest, const uint8_t* key, size_t keyLen)
{
  return verifySignature(parse(interest), key, keyLen);
}

bool
verifySignature(const Data& data, const v2::Certificate& cert)
{
  return verifySignature(parse(data), cert.getContent().value(), cert.getContent().value_size());
}

bool
verifySignature(const Interest& interest, const v2::Certificate& cert)
{
  return verifySignature(parse(interest), cert.getContent().value(), cert.getContent().value_size());
}

///////////////////////////////////////////////////////////////////////

bool
verifyDigest(const uint8_t* blob, size_t blobLen, const uint8_t* digest, size_t digestLen,
             DigestAlgorithm algorithm)
{
  using namespace transform;

  OBufferStream os;
  try {
    bufferSource(blob, blobLen) >> digestFilter(algorithm) >> streamSink(os);
  }
  catch (const transform::Error&) {
    return false;
  }
  ConstBufferPtr result = os.buf();

  if (result->size() != digestLen)
    return false;

  // constant-time buffer comparison to mitigate timing attacks
  return CRYPTO_memcmp(result->data(), digest, digestLen) == 0;
}

bool
verifyDigest(const Data& data, DigestAlgorithm algorithm)
{
  bool isParsable = false;
  const uint8_t* buf = nullptr;
  size_t bufLen = 0;
  const uint8_t* sig = nullptr;
  size_t sigLen = 0;

  std::tie(isParsable, buf, bufLen, sig, sigLen) = parse(data);

  if (isParsable) {
    return verifyDigest(buf, bufLen, sig, sigLen, algorithm);
  }
  else {
    return false;
  }
}

bool
verifyDigest(const Interest& interest, DigestAlgorithm algorithm)
{
  bool isParsable = false;
  const uint8_t* buf = nullptr;
  size_t bufLen = 0;
  const uint8_t* sig = nullptr;
  size_t sigLen = 0;

  std::tie(isParsable, buf, bufLen, sig, sigLen) = parse(interest);

  if (isParsable) {
    return verifyDigest(buf, bufLen, sig, sigLen, algorithm);
  }
  else {
    return false;
  }
}

} // namespace security
} // namespace ndn
