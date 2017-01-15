#include "generate_priv_key.h"
#include "prng.h"

#include <util/buffutil.h>
#include <epid/common/file_parser.h>
#include "epid/common/src/epid2params.h"
#include "epid/common/math/finitefield.h"
#include "epid/common/math/ecgroup.h"

#include <string.h>
#include <stdlib.h>

#define PUBKEYFILE_DEFAULT "pubkey.bin"

/// Handle SDK Error with Break
#define BREAK_ON_EPID_ERROR(ret) \
  if (kEpidNoErr != (ret)) {     \
    break;                       \
  }

typedef struct EpidGroupPubKeyCertificate {
  EpidFileHeader header;     ///< Intel(R) EPID binary file header
  GroupId gid;               ///< group ID
  G1ElemStr h1;              ///< an element in G1
  G1ElemStr h2;              ///< an element in G1
  G2ElemStr w;               ///< an element in G2
  EcdsaSignature signature;  ///< ECDSA Signature on SHA-256 of above values
} EpidGroupPubKeyCertificate;

int main()
{
    EpidStatus sts;
    JoinRequest join_request;
    int ret_value = EXIT_SUCCESS;

    // Group public key buffer
    static char* pubkey_file = NULL;
    if (!pubkey_file)
        pubkey_file = PUBKEYFILE_DEFAULT;
    void* signed_pubkey = NULL;
    size_t signed_pubkey_size = 0;
    GroupPubKey pub_key = {0};

    Epid2Params_* params = NULL;

    EcPoint* h1_pt = NULL;

    FfElement* f_el = NULL;
    BigNumStr f_str;

    EcPoint* f_pt = NULL;

    static const BigNumStr one = {
        {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}};

    do {
        // Get params (constants defined by Intel)
        sts = CreateEpid2Params(&params);
        BREAK_ON_EPID_ERROR(sts);
        if (!params->Fp || !params->G1) {
          sts = kEpidBadArgErr;
          break;
        }

        // Issuer
        // TODO: Create the public key, and get a new issuing_priv_key (i.e. gamma)
        // TODO: Create a GroupID (128-bit number that identifies this group)
        // TODO: Generate random h_1 and h_2 <- G_1
        // TODO: Generate random gamma <- F_p
        // TODO: Calculate w = (g_2)^gamma
        // TODO: Write gid (as GroupId), h_1, h_2, w (as strings) into a GroupPubKey
        // TODO: Write gid (as GroupId) and gamma (as string) into a IPrivKey
        // For now, Read-in public key
        signed_pubkey = NewBufferFromFile(pubkey_file, &signed_pubkey_size);
        if (!signed_pubkey) {
            ret_value = EXIT_FAILURE;
        }
        EpidGroupPubKeyCertificate* buf_pubkey = (EpidGroupPubKeyCertificate*)signed_pubkey;
        pub_key.gid = buf_pubkey->gid;
        pub_key.h1 = buf_pubkey->h1;
        pub_key.h2 = buf_pubkey->h2;
        pub_key.w = buf_pubkey->w;

        // Create two PRNGs (one for member, one for issuer)
        void* mem_prng = NULL;
        sts = PrngCreate(&mem_prng);
        if (kEpidNoErr != sts) {
            break;
        }
        void* iss_prng = NULL;
        sts = PrngCreate(&iss_prng);
        if (kEpidNoErr != sts) {
            break;
        }

        // Member
        // Get h1 from public key
        sts = NewEcPoint(params->G1, &h1_pt);
        BREAK_ON_EPID_ERROR(sts);
        sts = ReadEcPoint(params->G1, (uint8_t*)&pub_key.h1, sizeof(pub_key.h1),
                          h1_pt);
        BREAK_ON_EPID_ERROR(sts);

        // Choose random f <- F_p
        sts = NewFfElement(params->Fp, &f_el);
        BREAK_ON_EPID_ERROR(sts);
        // Step 1. The member chooses a random integer r from [1, p-1].
        sts = FfGetRandom(params->Fp, &one, PrngGen, mem_prng, f_el);
        BREAK_ON_EPID_ERROR(sts);
        sts = WriteFfElement(params->Fp, f_el, (uint8_t*)&f_str, sizeof(f_str));

        // Compute F = G1.sscmExp(h1, f).
        sts = NewEcPoint(params->G1, &f_pt);
        BREAK_ON_EPID_ERROR(sts);
        sts = EcExp(params->G1, h1_pt, (BigNumStr const*)&f_str, f_pt);
        BREAK_ON_EPID_ERROR(sts);

        // Issuer
        // TODO: Choose random x <- F_p
        // TODO: Calculate (g_1 * F)^(1/(x + gamma))

        // Finally
        // TODO: Set private_key = (gid, A, x, f)
        // TODO: (OPTIONAL) Verify pairing equality
    } while (0);

    if (kEpidNoErr != sts) {
        return 1;
    } else {
        return 0;
    }
}

