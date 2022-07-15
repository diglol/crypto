//
// Created by RobX on 2021/10/5.
//

#import "KeyPair.h"

@implementation KeyPair {
}

+ (instancetype)publicKeyWithPrivateKey:(NSData *)publicKey privateKey:(NSData *)privateKey {
    KeyPair *keyPair = [[KeyPair alloc] init];
    keyPair->_publicKey = publicKey;
    keyPair->_privateKey = privateKey;
    return keyPair;
}

- (NSData *)privateKey {
    return _privateKey;
}

- (NSData *)publicKey {
    return _publicKey;
}

@end