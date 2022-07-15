//
// Created by RobX on 2021/10/5.
//

#import "Ed25519.h"
#import "KeyPair.h"
#import "Random.h"

extern void edcurve25519_genpubkey(unsigned char *edcurve25519_pubkey_out, const unsigned char *edcurve25519_privkey_in);

extern int edcurve25519_sign(unsigned char *signature_out, unsigned long long *smlen, const unsigned char *edcurve25519_privkey, const unsigned char *msg, const unsigned long msg_len);

extern int edcurve25519_verify(const unsigned char *signature, const unsigned char *edcurve25519_pubkey, const unsigned char *msg, const unsigned long msg_len);

@implementation Ed25519 {
}

+ (KeyPair *)generateKeyPair {
    NSData *privateKey = [Random nextNsDataWithSize:KeySize];
    return [Ed25519 generateKeyPairWithPrivateKey:privateKey];
}

+ (KeyPair *)generateKeyPairWithPrivateKey:(NSData *)privateKey {
    unsigned char *publicKey = malloc(KeySize);
    edcurve25519_genpubkey(publicKey, privateKey.bytes);
    NSData *nsPublicKey = [NSData dataWithBytes:publicKey length:KeySize];
    free(publicKey);
    return [KeyPair publicKeyWithPrivateKey:nsPublicKey privateKey:privateKey];
}


+ (NSData *)signWithPrivateKey:(NSData *)privateKey data:(NSData *)data {
    uint8_t realKey[KeySize * 2];
    if (privateKey.length == KeySize * 2) {
        memmove(realKey, privateKey.bytes, KeySize * 2);
    } else {
        uint8_t publicKey[KeySize];
        edcurve25519_genpubkey(publicKey, privateKey.bytes);
        memmove(realKey, privateKey.bytes, KeySize);
        memmove(realKey + KeySize, publicKey, KeySize);
    }
    unsigned long long signatureSize;
    unsigned char *signature = malloc(SignatureSize + data.length);
    edcurve25519_sign(signature, &signatureSize, realKey, data.bytes, data.length);
    NSData *realSign = [NSData dataWithBytes:signature length:SignatureSize];
    free(signature);
    return realSign;
}

+ (NSData *)signWithKeyPair:(KeyPair *)keyPair data:(NSData *)data {
    uint8_t realKey[KeySize * 2];
    if (keyPair.publicKey != NULL) {
        memmove(realKey, keyPair.privateKey.bytes, KeySize);
        memmove(realKey + KeySize, keyPair.publicKey.bytes, KeySize);
    } else {
        uint8_t publicKey[KeySize];
        edcurve25519_genpubkey(publicKey, keyPair.privateKey.bytes);
        memmove(realKey, keyPair.privateKey.bytes, KeySize);
        memmove(realKey + KeySize, publicKey, KeySize);
    }
    unsigned long long signatureSize;
    unsigned char *signature = malloc(SignatureSize + data.length);
    edcurve25519_sign(signature, &signatureSize, realKey, data.bytes, data.length);
    NSData *realSign = [NSData dataWithBytes:signature length:SignatureSize];
    free(signature);
    return realSign;
}

+ (BOOL)verifyWithSignature:(NSData *)signature publicKey:(NSData *)publicKey data:(NSData *)data {
    return edcurve25519_verify(signature.bytes, publicKey.bytes, data.bytes, data.length) == 0;
}

@end
