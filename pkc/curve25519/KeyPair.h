//
// Created by RobX on 2021/10/5.
//

#import <Foundation/Foundation.h>

#define KeySize 32
#define SignatureSize 64

@interface KeyPair : NSObject {
    NSData *_publicKey;
    NSData *_privateKey;
}

+ (instancetype)publicKeyWithPrivateKey:(NSData *)publicKey privateKey:(NSData *)privateKey;

- (NSData *)privateKey;

- (NSData *)publicKey;

@end