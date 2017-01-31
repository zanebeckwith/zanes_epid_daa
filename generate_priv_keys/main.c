#include "generate_priv_key.h"
#include "prng.h"

#include <util/buffutil.h>
#include <epid/common/file_parser.h>
#include "epid/common/src/epid2params.h"
#include "epid/common/math/finitefield.h"
#include "epid/common/math/ecgroup.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define PUBKEYFILE_DEFAULT "pubkey.bin"

EpidStatus generate_group_key(GroupPubKey* gpk, IPrivKey* isk);

EpidStatus generate_new_private_key(GroupPubKey* gpk, IPrivKey* isk, PrivKey* priv_key);

EpidStatus save_group_key_to_file(GroupPubKey* gpk);

EpidStatus save_issuer_private_key_to_file(IPrivKey* isk);

EpidStatus save_member_private_key_to_file(PrivKey* priv_key);

int main()
{
    EpidStatus sts;

    GroupPubKey pub_key = {0};
    IPrivKey issuer_priv_key = {0};
    PrivKey priv_key = {0};

    do {
        sts = generate_group_key(&pub_key, &issuer_priv_key);
        if (kEpidNoErr != sts) {
            printf("Error generating group key: %s\n", EpidStatusToString(sts));
            break;
        }

        sts = generate_new_private_key(&pub_key, &issuer_priv_key, &priv_key);
        if (kEpidNoErr != sts) {
            printf("Error generating private key: %s\n", EpidStatusToString(sts));
            break;
        }

        sts = save_group_key_to_file(&pub_key);
        if (kEpidNoErr != sts) {
            printf("Error saving public key\n");
            break;
        }

        sts = save_issuer_private_key_to_file(&issuer_priv_key);
        if (kEpidNoErr != sts) {
            printf("Error saving issuer's private key\n");
            break;
        }

        sts = save_member_private_key_to_file(&priv_key);
        if (kEpidNoErr != sts) {
            printf("Error saving member's private key\n");
            break;
        }
    } while (0);

    if (kEpidNoErr != sts) {
        return 1;
    } else {
        return 0;
    }
}

EpidStatus generate_group_key(GroupPubKey* gpk, IPrivKey* isk)
{
    // Create the public key, and get a new issuing_priv_key (i.e. gamma)

    EpidStatus sts;
    void* prng = NULL;
    Epid2Params_* params = NULL;
    EcPoint* h1_pt = NULL;
    EcPoint* h2_pt = NULL;
    FfElement* gamma_el = NULL;
    EcPoint* w_pt = NULL;
    static const BigNumStr one = {
        {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}};

    do {
        // Create an instance of our pseudo-rng
        // TODO: Look into this
        sts = PrngCreate(&prng);
        if (kEpidNoErr != sts) {
            printf("Error creating prng: %s\n", EpidStatusToString(sts));
            break;
        }

        // Get params (constants defined by Intel)
        sts = CreateEpid2Params(&params);
        if (kEpidNoErr != sts) {
            printf("Error creating params: %s\n", EpidStatusToString(sts));
            break;
        }
        if (!params->Fp || !params->G1) {
            printf("Error with Fp or G1\n");
          sts = kEpidBadArgErr;
          break;
        }
        // Create a GroupID (128-bit number that identifies this group)
        // Write it into both the group public key and the issuer private key
        // TODO: Track allocated gid's, and use new ones for new groups
        // TODO: Check if memcpy's are ok to use (are there IPP primitives to use instead?)
        GroupId gid = {
            {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}};
        memcpy(gpk->gid.data, gid.data, 16);
        memcpy(isk->gid.data, gid.data, 16);

        // Generate random h_1, h_2 <- G_1
        // Save them into the group public key
        sts = NewEcPoint(params->G1, &h1_pt);
        if (kEpidNoErr != sts) {
            printf("Error allocating h1: %s\n", EpidStatusToString(sts));
            break;
        }
        sts = EcGetRandom(params->G1, PrngGen, prng, h1_pt);
        if (kEpidNoErr != sts) {
            printf("Error generating h1: %s\n", EpidStatusToString(sts));
            break;
        }
        sts = WriteEcPoint(params->G1, h1_pt, (uint8_t*)&gpk->h1, sizeof(gpk->h1));
        if (kEpidNoErr != sts) {
            printf("Error writing h1: %s\n", EpidStatusToString(sts));
            break;
        }
        sts = NewEcPoint(params->G1, &h2_pt);
        if (kEpidNoErr != sts) {
            printf("Error allocating h2: %s\n", EpidStatusToString(sts));
            break;
        }
        sts = EcGetRandom(params->G1, PrngGen, prng, h2_pt);
        if (kEpidNoErr != sts) {
            printf("Error generating h2: %s\n", EpidStatusToString(sts));
            break;
        }
        sts = WriteEcPoint(params->G1, h2_pt, (uint8_t*)&gpk->h2, sizeof(gpk->h2));
        if (kEpidNoErr != sts) {
            printf("Error writing h2: %s\n", EpidStatusToString(sts));
            break;
        }

        // Generate random gamma <- F_p
        // Save it into the issuer private key
        // TODO: Are we sure this should be from F_p, and not F_q2?
        sts = NewFfElement(params->Fp, &gamma_el);
        if (kEpidNoErr != sts) {
            printf("Error allocating gamma: %s\n", EpidStatusToString(sts));
            break;
        }
        // TODO: 'one' is the lower-bound; should I change its value?
        sts = FfGetRandom(params->Fp, &one, PrngGen, prng, gamma_el);
        if (kEpidNoErr != sts) {
            printf("Error generating gamma: %s\n", EpidStatusToString(sts));
            break;
        }
        sts = WriteFfElement(params->Fp, gamma_el, (uint8_t*)&isk->gamma, sizeof(isk->gamma));
        if (kEpidNoErr != sts) {
            printf("Error writing gamma: %s\n", EpidStatusToString(sts));
            break;
        }

        // Calculate w = (g_2)^gamma
        // Write it into the group public key
        sts = NewEcPoint(params->G2, &w_pt);
        if (kEpidNoErr != sts) {
            printf("Error allocating w: %s\n", EpidStatusToString(sts));
            break;
        }
        sts = EcExp(params->G2, params->g2, (BigNumStr const*)&isk->gamma, w_pt);
        if (kEpidNoErr != sts) {
            printf("Error calculating w=h2^gamma: %s\n", EpidStatusToString(sts));
            break;
        }
        sts = WriteEcPoint(params->G2, w_pt, (uint8_t*)&gpk->w, sizeof(gpk->w));
        if (kEpidNoErr != sts) {
            printf("Error writing w: %s\n", EpidStatusToString(sts));
            break;
        }
    } while (0);

    PrngDelete(&prng);
    DeleteEpid2Params(&params);
    DeleteEcPoint(&h1_pt);
    DeleteEcPoint(&h2_pt);
    DeleteFfElement(&gamma_el);
    DeleteEcPoint(&w_pt);

    return sts;
}



EpidStatus generate_new_private_key(GroupPubKey* gpk, IPrivKey* isk, PrivKey* priv_key)
{
    EpidStatus sts;
    void* prng = NULL;
    Epid2Params_* params = NULL;
    EcPoint* h1_pt = NULL;
    FfElement* f_el = NULL;
    BigNumStr f_str;
    EcPoint* f_pt = NULL;
    FfElement* x_el = NULL;
    FfElement* gamma_el = NULL;
    FfElement* sum_el = NULL;
    FfElement* inv_el = NULL;
    BigNumStr inv_str;
    EcPoint* gf_pt = NULL;
    EcPoint* a_pt = NULL;
    static const BigNumStr one = {
        {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}};

    do {
        // Create an instance of our pseudo-rng
        // TODO: Look into this
        sts = PrngCreate(&prng);
        if (kEpidNoErr != sts) {
            printf("Error creating prng: %s\n", EpidStatusToString(sts));
            break;
        }

        // Get params (constants defined by Intel)
        sts = CreateEpid2Params(&params);
        if (kEpidNoErr != sts) {
            printf("Error creating params: %s\n", EpidStatusToString(sts));
            break;
        }
        if (!params->Fp || !params->G1) {
            printf("Error with Fp or G1\n");
          sts = kEpidBadArgErr;
          break;
        }

        // Get h1 from public key
        sts = NewEcPoint(params->G1, &h1_pt);
        if (kEpidNoErr != sts) {
            printf("Error allocating h1: %s\n", EpidStatusToString(sts));
            break;
        }
        sts = ReadEcPoint(params->G1, (uint8_t*)&gpk->h1, sizeof(gpk->h1), h1_pt);
        if (kEpidNoErr != sts) {
            printf("Error reading h1: %s\n", EpidStatusToString(sts));
            break;
        }

        // Choose random f <- F_p (member)
        sts = NewFfElement(params->Fp, &f_el);
        if (kEpidNoErr != sts) {
            printf("Error allocating f: %s\n", EpidStatusToString(sts));
            break;
        }
        sts = FfGetRandom(params->Fp, &one, PrngGen, prng, f_el);
        if (kEpidNoErr != sts) {
            printf("Error generating f: %s\n", EpidStatusToString(sts));
            break;
        }
        sts = WriteFfElement(params->Fp, f_el, (uint8_t*)&f_str, sizeof(f_str));
        if (kEpidNoErr != sts) {
            printf("Error writing f: %s\n", EpidStatusToString(sts));
            break;
        }

        // Compute F = G1.sscmExp(h1, f) (member)
        sts = NewEcPoint(params->G1, &f_pt);
        if (kEpidNoErr != sts) {
            printf("Error allocating F: %s\n", EpidStatusToString(sts));
            break;
        }
        sts = EcExp(params->G1, h1_pt, (BigNumStr const*)&f_str, f_pt);
        if (kEpidNoErr != sts) {
            printf("Error calculating F=h1^f: %s\n", EpidStatusToString(sts));
            break;
        }

        // Choose random x <- F_p (issuer)
        sts = NewFfElement(params->Fp, &x_el);
        if (kEpidNoErr != sts) {
            printf("Error allocating x: %s\n", EpidStatusToString(sts));
            break;
        }
        sts = FfGetRandom(params->Fp, &one, PrngGen, prng, x_el);
        if (kEpidNoErr != sts) {
            printf("Error generating x: %s\n", EpidStatusToString(sts));
            break;
        }

        // Calculate A = (g_1 * F)^(1/(x + gamma)) (issuer)
        // 1) Calculate x + gamma
        sts = NewFfElement(params->Fp, &gamma_el);
        if (kEpidNoErr != sts) {
            printf("Error allocating gamma: %s\n", EpidStatusToString(sts));
            break;
        }
        sts = ReadFfElement(params->Fp, (uint8_t*)&isk->gamma, sizeof(isk->gamma), gamma_el);
        if (kEpidNoErr != sts) {
            printf("Error reading gamma: %s\n", EpidStatusToString(sts));
            break;
        }
        sts = NewFfElement(params->Fp, &sum_el);
        if (kEpidNoErr != sts) {
            printf("Error allocating intermediate sum_el: %s\n", EpidStatusToString(sts));
            break;
        }
        sts = FfAdd(params->Fp, x_el, gamma_el, sum_el);
        if (kEpidNoErr != sts) {
            printf("Error calculating gamma + x: %s\n", EpidStatusToString(sts));
            break;
        }

        // 2) Calculate 1 / (x + gamma)
        sts = NewFfElement(params->Fp, &inv_el);
        if (kEpidNoErr != sts) {
            printf("Error allocating intermediate inv_el: %s\n", EpidStatusToString(sts));
            break;
        }
        sts = FfInv(params->Fp, sum_el, inv_el);
        if (kEpidNoErr != sts) {
            printf("Error calculating 1 / (gamma + x): %s\n", EpidStatusToString(sts));
            break;
        }
        sts = WriteFfElement(params->Fp, inv_el, (uint8_t*)&inv_str, sizeof(inv_str));
        if (kEpidNoErr != sts) {
            printf("Error writing 1/(x+gamma) to a temporary string: %s\n", EpidStatusToString(sts));
            break;
        }

        // 3) Calculate g_1 * F
        sts = NewEcPoint(params->G1, &gf_pt);
        if (kEpidNoErr != sts) {
            printf("Error allocating g_1*F: %s\n", EpidStatusToString(sts));
            break;
        }
        sts = EcMul(params->G1, params->g1, f_pt, gf_pt);
        if (kEpidNoErr != sts) {
            printf("Error calculating g_1*F: %s\n", EpidStatusToString(sts));
            break;
        }

        // 4) Calculate A = (g_1*F)^1/(x+gamma)
        sts = NewEcPoint(params->G1, &a_pt);
        if (kEpidNoErr != sts) {
            printf("Error allocating A: %s\n", EpidStatusToString(sts));
            break;
        }
        sts = EcExp(params->G1, gf_pt, (BigNumStr const*)&inv_str, a_pt);
        if (kEpidNoErr != sts) {
            printf("Error calculating A=(g_1*F)^1/(x+gamma): %s\n", EpidStatusToString(sts));
            break;
        }

        // Set private_key = (gid, A, x, f)
        memcpy(priv_key->gid.data, gpk->gid.data, 16);
        sts = WriteEcPoint(params->G1, a_pt, (uint8_t*)&priv_key->A, sizeof(priv_key->A));
        if (kEpidNoErr != sts) {
            printf("Error writing A to private key: %s\n", EpidStatusToString(sts));
            break;
        }
        sts = WriteFfElement(params->Fp, x_el, (uint8_t*)&priv_key->x, sizeof(priv_key->x));
        if (kEpidNoErr != sts) {
            printf("Error writing x to private key: %s\n", EpidStatusToString(sts));
            break;
        }
        sts = WriteFfElement(params->Fp, f_el, (uint8_t*)&priv_key->f, sizeof(priv_key->f));
        if (kEpidNoErr != sts) {
            printf("Error writing f to private key: %s\n", EpidStatusToString(sts));
            break;
        }

        // TODO: (OPTIONAL) Verify pairing equality
    } while (0);

    PrngDelete(&prng);
    DeleteEpid2Params(&params);
    DeleteEcPoint(&h1_pt);
    DeleteFfElement(&f_el);
    DeleteEcPoint(&f_pt);
    DeleteFfElement(&gamma_el);
    DeleteFfElement(&sum_el);
    DeleteFfElement(&inv_el);
    DeleteEcPoint(&gf_pt);
    DeleteEcPoint(&a_pt);

    return sts;
}

EpidStatus save_group_key_to_file(GroupPubKey* gpk)
{
    FILE *fil = fopen("pubkey.bin", "wb");
    fwrite(gpk, 1, sizeof(GroupPubKey), fil);

    return kEpidNoErr;
}

EpidStatus save_issuer_private_key_to_file(IPrivKey* isk)
{
    FILE *fil = fopen("iprivkey.dat", "wb");
    fwrite(isk, 1, sizeof(IPrivKey), fil);

    return kEpidNoErr;
}

EpidStatus save_member_private_key_to_file(PrivKey* priv_key)
{
    FILE *fil = fopen("mprivkey.dat", "wb");
    fwrite(priv_key, 1, sizeof(PrivKey), fil);

    return kEpidNoErr;
}

