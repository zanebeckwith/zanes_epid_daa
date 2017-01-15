/*############################################################################
  # Copyright 2016 Intel Corporation
  #
  # Licensed under the Apache License, Version 2.0 (the "License");
  # you may not use this file except in compliance with the License.
  # You may obtain a copy of the License at
  #
  #     http://www.apache.org/licenses/LICENSE-2.0
  #
  # Unless required by applicable law or agreed to in writing, software
  # distributed under the License is distributed on an "AS IS" BASIS,
  # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  # See the License for the specific language governing permissions and
  # limitations under the License.
  ############################################################################*/
#ifndef EPID_MEMBER_API_H_
#define EPID_MEMBER_API_H_

#include <stddef.h>
#include "epid/common/stdtypes.h"
#include "epid/common/types.h"
#include "epid/common/errors.h"
#include "epid/common/bitsupplier.h"

/*!
 * \file
 * \brief Intel(R) EPID SDK member API.
 */

/// Member functionality
/*!
  \defgroup EpidMemberModule member

  Defines the APIs needed by Intel(R) EPID members. Each member
  context (::MemberCtx) represents membership in a single group.

  \ingroup EpidModule
  @{
*/

/// Creates a request to join a group.
/*!
 The created request is part of the interaction with an issuer needed to join
 a group. This interaction with the issuer is outside the scope of this API.

 \param[in] pub_key
 The group certificate of group to join.
 \param[in] ni
 The nonce chosen by issuer as part of join protocol.
 \param[in] f
 A randomly selected integer in [1, p-1].
 \param[in] rnd_func
 Random number generator.
 \param[in] rnd_param
 Pass through context data for rnd_func.
 \param[in] hash_alg
 The hash algorithm to be used.
 \param[out] join_request
 The join request.

 \returns ::EpidStatus

 \warning
 For security rnd_func should be a cryptographically secure random
 number generator.

 \note
 The default hash algorithm in Member is SHA-512. This is the
 recommended option if you do not override the hash algorithm
 elsewhere.

 \note
 If the result is not ::kEpidNoErr, the content of join_request is undefined.

 \see ::HashAlg
 */
EpidStatus EpidRequestJoin(GroupPubKey const* pub_key, IssuerNonce const* ni,
                           FpElemStr const* f, BitSupplier rnd_func,
                           void* rnd_param, HashAlg hash_alg,
                           JoinRequest* join_request);

/*! @} */
#endif  // EPID_MEMBER_API_H_
