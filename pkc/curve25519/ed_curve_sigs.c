#include <string.h>
#include <stdlib.h>
#include "ge.h"
#include "crypto_sign.h"
#include "crypto_hash_sha512.h"

void edcurve25519_genpubkey(unsigned char *edcurve25519_pubkey_out,
        const unsigned char *edcurve25519_privkey_in) {
    unsigned char *hashed_privkey = malloc(64);
    crypto_hash_sha512(hashed_privkey, edcurve25519_privkey_in, 32);
    hashed_privkey[0] &= 248;
    hashed_privkey[31] &= 63;
    hashed_privkey[31] |= 64;
    ge_p3 ed_pubkey_point; /* Ed25519 pubkey point */
    ge_scalarmult_base(&ed_pubkey_point, hashed_privkey);
    free(hashed_privkey);
    ge_p3_tobytes(edcurve25519_pubkey_out, &ed_pubkey_point);
}

int edcurve25519_sign(unsigned char *signature_out,
        unsigned long long *smlen,
        const unsigned char *edcurve25519_key,
        const unsigned char *msg, const unsigned long msg_len) {
    return crypto_sign(signature_out, smlen, msg, msg_len, edcurve25519_key);
}

int edcurve25519_verify(const unsigned char *signature,
        const unsigned char *edcurve25519_pubkey,
        const unsigned char *msg, const unsigned long msg_len) {
    unsigned long long some_retval;
    unsigned char *verifybuf = NULL; /* working buffer */
    unsigned char *verifybuf2 = NULL; /* working buffer #2 */
    int result;

    if ((verifybuf = malloc(msg_len + 64)) == 0) {
        result = -1;
        goto err;
    }

    if ((verifybuf2 = malloc(msg_len + 64)) == 0) {
        result = -1;
        goto err;
    }

    memmove(verifybuf, signature, 64);
    verifybuf[63] &= 0x7F;

    memmove(verifybuf + 64, msg, msg_len);

    /* Then perform a normal Ed25519 verification, return 0 on success */
    /* The below call has a strange API: */
    /* verifybuf = R || S || message */
    /* verifybuf2 = internal to next call gets a copy of verifybuf, S gets
       replaced with pubkey for hashing, then the whole thing gets zeroized
       (if bad sig), or contains a copy of msg (good sig) */
    result = crypto_sign_open(verifybuf2, &some_retval, verifybuf, 64 + msg_len, edcurve25519_pubkey);

    err:

    if (verifybuf != NULL) {
        free(verifybuf);
    }

    if (verifybuf2 != NULL) {
        free(verifybuf2);
    }

    return result;
}
