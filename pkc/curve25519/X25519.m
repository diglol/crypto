//
// Created by RobX on 2021/10/5.
//

#import "X25519.h"
#import "KeyPair.h"
#import "Random.h"

extern void curve25519_donna(unsigned char *output, const unsigned char *a, const unsigned char *b);

@implementation X25519 : NSObject {
}

+ (KeyPair *)generateKeyPair {
    uint8_t privateKey[KeySize];
    memcpy(privateKey, [Random nextNsDataWithSize:KeySize].bytes, KeySize);
    privateKey[0] &= 248;
    privateKey[31] &= 127;
    privateKey[31] |= 64;
    return [X25519 generateKeyPairWithPrivateKey:[NSData dataWithBytes:privateKey length:KeySize]];
}

+ (KeyPair *)generateKeyPairWithPrivateKey:(NSData *)privateKey {
    uint8_t publicKey[KeySize];
    static const uint8_t basepoint[KeySize] = {9};
    curve25519_donna(publicKey, privateKey.bytes, basepoint);
    return [KeyPair publicKeyWithPrivateKey:[NSData dataWithBytes:publicKey length:KeySize] privateKey:privateKey];
}


+ (NSData *)computeSharedSecretWithPrivateKey:(NSData *)privateKey peersPublicKey:(NSData *)peersPublicKey {
    uint8_t sharedSecret[KeySize];
    curve25519_donna(sharedSecret, privateKey.bytes, peersPublicKey.bytes);
    return [NSData dataWithBytes:sharedSecret length:KeySize];
}

@end