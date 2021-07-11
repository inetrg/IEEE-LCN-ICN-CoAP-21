/* Security contexts */

#include <oscore/contextpair.h>
#include <oscore/context_impl/primitive.h>
#include <oscore/context_impl/groupprimitive.h>
#include <oscore/context_impl/pairwiseprimitive.h>

#include <assert.h>

// from https://github.com/ace-wg/Hackathon-109/blob/master/GroupKeys.md: Rikard Test 2 Entity 1
//
// For the tests, it is sufficient to have the same public / private key pair
// for every participant, as there is only one actually signing context anyway.
static uint8_t public[32] = {206, 97, 111, 40, 66, 110, 242, 78, 219, 81, 219, 206, 247, 162, 51, 5, 248, 134, 246, 87, 149, 157, 77, 248, 137, 221, 252, 2, 85, 4, 33, 89};
static uint8_t private[32] = {57, 124, 235, 90, 141, 33, 215, 74, 146, 88, 194, 12, 51, 252, 69, 171, 21, 43, 2, 207, 71, 155, 46, 48, 129, 40, 95, 119, 69, 76, 243, 71};

static const uint8_t *mastersecret = (uint8_t*)"mastersecret";
static const size_t mastersecret_len = 12;
static const uint8_t *mastersalt = (uint8_t*)"mastersalt";
static const uint8_t mastersalt_len = 10;

struct oscore_context_groupprimitive_immutables_sender groupsender_immutable = {
    /* sent with every request, can tune length; 1 sounds realistic given that
     * it's all unicast so we can have it real short (but nonzero so it can
     * change for rekeyings) */
    .gid = (uint8_t*)"g",
    .gid_len = 1,
    .aeadalg = 10 /* AES-CCM */,
    .signalgpar = {.algo = COSE_ALGO_EDDSA, .crv = COSE_EC_CURVE_ED25519, },
    .key = {
        .algo = COSE_ALGO_EDDSA, .crv = COSE_EC_CURVE_ED25519,
        .x = public,
        .d = private,
    }
};
struct oscore_context_groupprimitive_sender groupsender = {
    .immutables = &groupsender_immutable,
};
struct oscore_context_groupprimitive_immutables_peer grouppeer_immutable = {
    .key = {
        .algo = COSE_ALGO_EDDSA, .crv = COSE_EC_CURVE_ED25519,
        .x = public,
    }
};
struct oscore_context_groupprimitive_peer grouppeer = {
    .immutables = &grouppeer_immutable,
};
struct oscore_context_groupprimitive_pair groupdata = {
    .sender = &groupsender,
    .peer = &grouppeer,
};

oscore_context_t groupcontext = {
    .type = OSCORE_CONTEXT_GROUPPRIMITIVE_PAIR,
    .data = (void*)(&groupdata),
};


struct oscore_context_primitive_immutables detdata_immutable;
struct oscore_context_pairwise detdata;

oscore_context_t detcontext = {
    .type = OSCORE_CONTEXT_PAIRWISEPRIMITIVE_PAIR,
    .data = (void*)(&detdata),
};

const oscore_crypto_hkdfalg_t hkdfalg = 5 /* or -10? HKDF SHA-256 */;

void configure_pairwise_for_hash(uint8_t *requesthash, size_t requesthash_len);

void set_up_contexts(bool is_client) {
    oscore_cryptoerr_t oscerr;

    if (is_client) {
        groupsender_immutable.sender_id[0] = 'd';
        groupsender_immutable.sender_id_len = 1;
        grouppeer_immutable.recipient_id[0] = 'c';
        grouppeer_immutable.recipient_id_len = 1;
    } else {
        groupsender_immutable.sender_id[0] = 'c';
        groupsender_immutable.sender_id_len = 1;
        grouppeer_immutable.recipient_id[0] = 'd';
        grouppeer_immutable.recipient_id_len = 1;
    }

    // Algorithm and IDs are already set; sender, recipient key and common IV can be derived
    oscerr = oscore_context_groupprimitive_derive_sender(
            &groupsender_immutable,
            hkdfalg,
            mastersalt, sizeof(mastersalt_len),
            mastersecret, sizeof(mastersecret_len)
            );
    assert(!oscore_cryptoerr_is_error(oscerr));

    oscerr = oscore_context_groupprimitive_derive_peer(
            &groupsender_immutable,
            &grouppeer_immutable,
            hkdfalg,
            mastersalt, sizeof(mastersalt_len),
            mastersecret, sizeof(mastersecret_len)
            );
    assert(!oscore_cryptoerr_is_error(oscerr));

    // Prepare always-constant parts of deterministic context

    detdata.primitive.immutables = &detdata_immutable;
    detdata.gid = groupsender_immutable.gid;
    detdata.gid_len = groupsender_immutable.gid_len;
    detdata.signalgpar = groupsender_immutable.signalgpar;

    detdata_immutable.aeadalg = groupsender_immutable.aeadalg;
    memcpy(&detdata_immutable.sender_id, groupsender_immutable.sender_id, groupsender_immutable.sender_id_len);
    detdata_immutable.sender_id_len = groupsender_immutable.sender_id_len;
    memcpy(&detdata_immutable.recipient_id, grouppeer_immutable.recipient_id, grouppeer_immutable.recipient_id_len);
    detdata_immutable.recipient_id_len = grouppeer_immutable.recipient_id_len;

//     printf("send key %02x %02x...\n", groupsender_immutable.sender_key[0], groupsender_immutable.sender_key[1]);
//     printf("peer key %02x %02x...\n", grouppeer_immutable.recipient_key[0], grouppeer_immutable.recipient_key[1]);
// 
//     // Now for any hash, we're ready for whichever hash to work with on the fly, eg.
//     prepare_pairwise_for_hash();
//     configure_pairwise_for_hash((uint8_t*)"foo", 3);
// 
//     printf("r send key %02x %02x...\n", detdata_immutable.sender_key[0], detdata_immutable.sender_key[1]);
//     printf("r peer key %02x %02x...\n", detdata_immutable.recipient_key[0], detdata_immutable.recipient_key[1]);
}

void prepare_pairwise_for_hash(void) {
    detdata.primitive.sender_sequence_number = 0;
    detdata.primitive.replay_window_left_edge = 0;
    detdata.primitive.replay_window = 0;
}

void configure_pairwise_for_hash(uint8_t *requesthash, size_t requesthash_len) {
    oscore_context_pairwise_derive(
            &detdata_immutable,
            &detdata,
            hkdfalg,
            &groupdata,
            requesthash,
            requesthash_len
            );
}
