
#ifndef __ED_CURVE_SIGS_H__
#define __ED_CURVE_SIGS_H__

void edcurve25519_genpubkey(unsigned char *edcurve25519_pubkey_out, /* 32 bytes */
        const unsigned char *edcurve25519_privkey_in); /* 32 bytes */

/* returns 0 on success */
int edcurve25519_sign(unsigned char *signature_out, /* 64 bytes */
        unsigned long long *smlen,
        const unsigned char *edcurve25519_key, /* prikey|pubkey 64 bytes */
        const unsigned char *msg, const unsigned long msg_len);

/* returns 0 on success */
int edcurve25519_verify(const unsigned char *signature, /* 64 bytes */
        const unsigned char *edcurve25519_pubkey, /* 32 bytes */
        const unsigned char *msg, const unsigned long msg_len);

#endif
