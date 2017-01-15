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

/*!
 * \file
 * \brief EpidRequestJoin implementation.
 */

#include "generate_priv_key.h"
#include <string.h>
#include "epid/common/src/epid2params.h"
#include "epid/common/math/finitefield.h"
#include "epid/common/math/ecgroup.h"

#pragma pack(1)
/// Storage for values to create commitment in Sign and Verify algorithms
typedef struct JoinPCommitValues {
  BigNumStr p;     ///< Intel(R) EPID 2.0 parameter p
  G1ElemStr g1;    ///< Intel(R) EPID 2.0 parameter g1
  G2ElemStr g2;    ///< Intel(R) EPID 2.0 parameter g2
  G1ElemStr h1;    ///< Group public key value h1
  G1ElemStr h2;    ///< Group public key value h2
  G2ElemStr w;     ///< Group public key value w
  G1ElemStr F;     ///< Variable F computed in algorithm
  G1ElemStr R;     ///< Variable R computed in algorithm
  IssuerNonce NI;  ///< Nonce
} JoinPCommitValues;
#pragma pack()

/// Handle SDK Error with Break
#define BREAK_ON_EPID_ERROR(ret) \
  if (kEpidNoErr != (ret)) {     \
    break;                       \
  }

EpidStatus EpidRequestJoin(GroupPubKey const* pub_key, IssuerNonce const* ni,
                           FpElemStr const* f, BitSupplier rnd_func,
                           void* rnd_param, HashAlg hash_alg,
                           JoinRequest* join_request) {
  EpidStatus sts;
  static const BigNumStr one = {
      {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}};
  BigNumStr r_str;
  JoinPCommitValues commit_values;
  Epid2Params_* params = NULL;
  FfElement* r_el = NULL;
  FfElement* f_el = NULL;
  FfElement* c_el = NULL;
  FfElement* cf_el = NULL;
  FfElement* s_el = NULL;
  EcPoint* f_pt = NULL;
  EcPoint* r_pt = NULL;
  EcPoint* h1_pt = NULL;

  if (!pub_key || !ni || !f || !rnd_func || !join_request) {
    return kEpidBadArgErr;
  }
  if (kSha256 != hash_alg && kSha384 != hash_alg && kSha512 != hash_alg) {
    return kEpidBadArgErr;
  }

  do {
    sts = CreateEpid2Params(&params);
    BREAK_ON_EPID_ERROR(sts);
    if (!params->Fp || !params->G1) {
      sts = kEpidBadArgErr;
      break;
    }
    sts = NewFfElement(params->Fp, &r_el);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewFfElement(params->Fp, &f_el);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewFfElement(params->Fp, &c_el);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewFfElement(params->Fp, &cf_el);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewFfElement(params->Fp, &s_el);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewEcPoint(params->G1, &f_pt);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewEcPoint(params->G1, &h1_pt);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewEcPoint(params->G1, &r_pt);
    BREAK_ON_EPID_ERROR(sts);

    sts = ReadFfElement(params->Fp, (uint8_t const*)f, sizeof(*f), f_el);
    BREAK_ON_EPID_ERROR(sts);
    sts = ReadEcPoint(params->G1, (uint8_t*)&pub_key->h1, sizeof(pub_key->h1),
                      h1_pt);
    BREAK_ON_EPID_ERROR(sts);

    // Step 1. The member chooses a random integer r from [1, p-1].
    sts = FfGetRandom(params->Fp, &one, rnd_func, rnd_param, r_el);
    BREAK_ON_EPID_ERROR(sts);
    sts = WriteFfElement(params->Fp, r_el, (uint8_t*)&r_str, sizeof(r_str));

    // Step 2. The member computes F = G1.sscmExp(h1, f).
    sts = EcExp(params->G1, h1_pt, (BigNumStr const*)f, f_pt);
    BREAK_ON_EPID_ERROR(sts);

    // Step 3. The member computes R = G1.sscmExp(h1, r).
    sts = EcExp(params->G1, h1_pt, (BigNumStr const*)&r_str, r_pt);
    BREAK_ON_EPID_ERROR(sts);

    // Step 4. The member computes c = Fp.hash(p || g1 || g2 || h1 || h2 || w ||
    // F || R || NI). Refer to Section 7.1 for hash operation over a prime
    // field.
    sts = WriteBigNum(params->p, sizeof(commit_values.p),
                      (uint8_t*)&commit_values.p);
    BREAK_ON_EPID_ERROR(sts);
    sts = WriteEcPoint(params->G1, params->g1, (uint8_t*)&commit_values.g1,
                       sizeof(commit_values.g1));
    BREAK_ON_EPID_ERROR(sts);
    sts = WriteEcPoint(params->G2, params->g2, (uint8_t*)&commit_values.g2,
                       sizeof(commit_values.g2));
    BREAK_ON_EPID_ERROR(sts);
    commit_values.h1 = pub_key->h1;
    commit_values.h2 = pub_key->h2;
    commit_values.w = pub_key->w;
    sts = WriteEcPoint(params->G1, f_pt, (uint8_t*)&commit_values.F,
                       sizeof(commit_values.F));
    BREAK_ON_EPID_ERROR(sts);
    sts = WriteEcPoint(params->G1, r_pt, (uint8_t*)&commit_values.R,
                       sizeof(commit_values.R));
    BREAK_ON_EPID_ERROR(sts);
    commit_values.NI = *ni;
    sts = FfHash(params->Fp, (uint8_t*)&commit_values, sizeof(commit_values),
                 hash_alg, c_el);
    BREAK_ON_EPID_ERROR(sts);

    // Step 5. The member computes s = (r + c * f) mod p.
    sts = FfMul(params->Fp, c_el, f_el, cf_el);
    BREAK_ON_EPID_ERROR(sts);
    sts = FfAdd(params->Fp, r_el, cf_el, s_el);
    BREAK_ON_EPID_ERROR(sts);

    // Step 6. The output join request is (F, c, s).
    sts = WriteFfElement(params->Fp, c_el, (uint8_t*)&join_request->c,
                         sizeof(join_request->c));
    BREAK_ON_EPID_ERROR(sts);
    sts = WriteFfElement(params->Fp, s_el, (uint8_t*)&join_request->s,
                         sizeof(join_request->s));
    BREAK_ON_EPID_ERROR(sts);
    sts = WriteEcPoint(params->G1, f_pt, (uint8_t*)&join_request->F,
                       sizeof(join_request->F));
    BREAK_ON_EPID_ERROR(sts);

    sts = kEpidNoErr;
  } while (0);
  DeleteEcPoint(&h1_pt);
  DeleteEcPoint(&r_pt);
  DeleteEcPoint(&f_pt);
  DeleteFfElement(&s_el);
  DeleteFfElement(&cf_el);
  DeleteFfElement(&c_el);
  DeleteFfElement(&f_el);
  DeleteFfElement(&r_el);
  DeleteEpid2Params(&params);
  return sts;
}

