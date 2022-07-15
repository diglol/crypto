//
// Created by RobX on 2021/10/5.
//

#import <Foundation/Foundation.h>

@class KeyPair;

@interface Ed25519 : NSObject
+ (KeyPair *)generateKeyPair;

+ (KeyPair *)generateKeyPairWithPrivateKey:(NSData *)privateKey;

+ (NSData *)signWithPrivateKey:(NSData *)privateKey data:(NSData *)data;

+ (NSData *)signWithKeyPair:(KeyPair *)keyPair data:(NSData *)data;

+ (BOOL)verifyWithSignature:(NSData *)signature publicKey:(NSData *)publicKey data:(NSData *)data;
@end
