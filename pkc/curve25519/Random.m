//
// Created by RobX on 2021/10/5.
//

#import "Random.h"

@implementation Random {
}

+ (NSData *)nextNsDataWithSize:(NSUInteger)size {
    NSMutableData *data = [NSMutableData dataWithLength:size];
    SecRandomCopyBytes(kSecRandomDefault, size, [data mutableBytes]);
    return [NSData dataWithData:data];
}

@end