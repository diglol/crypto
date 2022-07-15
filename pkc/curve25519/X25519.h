//
// Created by RobX on 2021/10/5.
//

#import <Foundation/Foundation.h>

@class KeyPair;

@interface X25519 : NSObject
+ (KeyPair *)generateKeyPair;

+ (KeyPair *)generateKeyPairWithPrivateKey:(NSData *)privateKey;

+ (NSData *)computeSharedSecretWithPrivateKey:(NSData *)privateKey peersPublicKey:(NSData *)peersPublicKey;
@end