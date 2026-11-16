#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>

static NSData *canonical(id value) {
    return [NSJSONSerialization dataWithJSONObject:value options:NSJSONWritingSortedKeys error:nil];
}
static NSString *sha(NSData *data) {
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];CC_SHA256(data.bytes,(CC_LONG)data.length,digest);
    NSMutableString *hex=[NSMutableString new];for(unsigned i=0;i<sizeof(digest);i++)[hex appendFormat:@"%02x",digest[i]];return hex;
}
int main(void) {@autoreleasepool {
    NSDictionary *request=[NSJSONSerialization JSONObjectWithData:[NSFileHandle.fileHandleWithStandardInput readDataToEndOfFile] options:0 error:nil];
    NSDictionary *answer=nil;
    @try {
        if([request[@"op"] isEqual:@"anchor"]) {
            NSDictionary *a=request[@"anchor"];
            NSData *keyData=[NSData dataWithContentsOfFile:@"/Library/Application Support/ActivityObserver/public-key.der"];
            NSString *fingerprint=request[@"expectedKey"];
            if(![fingerprint isKindOfClass:NSString.class] || [fingerprint rangeOfString:@"^[a-f0-9]{64}$" options:NSRegularExpressionSearch].location==NSNotFound)@throw @"expected_key_required";
            if(![sha(keyData) isEqual:fingerprint]||![a[@"key_fingerprint"] isEqual:fingerprint]||![a[@"algorithm"] isEqual:@"ECDSA-P256-SHA256"])@throw @"key_or_algorithm_mismatch";
            NSDictionary *attrs=@{(__bridge id)kSecAttrKeyType:(__bridge id)kSecAttrKeyTypeECSECPrimeRandom,(__bridge id)kSecAttrKeyClass:(__bridge id)kSecAttrKeyClassPublic,(__bridge id)kSecAttrKeySizeInBits:@256};
            SecKeyRef key=SecKeyCreateWithData((__bridge CFDataRef)keyData,(__bridge CFDictionaryRef)attrs,NULL);
            NSData *sig=[[NSData alloc] initWithBase64EncodedString:a[@"signature"] options:0];
            BOOL valid=key&&sig&&SecKeyVerifySignature(key,kSecKeyAlgorithmECDSASignatureMessageX962SHA256,(__bridge CFDataRef)canonical(a[@"payload"]),(__bridge CFDataRef)sig,NULL);
            if(key)CFRelease(key);if(!valid)@throw @"anchor_signature_invalid";
            answer=@{@"valid":@YES};
        } else if([request[@"op"] isEqual:@"page"]) {
            NSArray *rows=request[@"rows"];if(rows.count>500)@throw @"page_limit";
            NSString *previous=request[@"previous"];NSMutableDictionary *checkpoints=[NSMutableDictionary new];
            NSSet *ids=[NSSet setWithArray:request[@"checkpoints"] ?: @[]];
            for(NSDictionary *r in rows) {@autoreleasepool {
                NSMutableDictionary *payload=[NSMutableDictionary new];
                for(NSString *k in @[@"id",@"first",@"last",@"day",@"kind",@"app",@"pid",@"path",@"source",@"detail",@"priority",@"count"])payload[k]=r[k] ?: NSNull.null;
                NSString *body=[[NSString alloc] initWithData:canonical(payload) encoding:NSUTF8StringEncoding];
                NSString *computed=sha([[NSString stringWithFormat:@"ActivityObserver-event-v1\n%@\n%@",previous,body] dataUsingEncoding:NSUTF8StringEncoding]);
                if(![r[@"chain_prev"] isEqual:previous]||![r[@"chain_hash"] isEqual:computed])@throw [NSString stringWithFormat:@"event_hash_mismatch:%@",r[@"id"]];
                previous=computed;if([ids containsObject:r[@"id"]])checkpoints[[r[@"id"] stringValue]]=computed;
            }}
            answer=@{@"valid":@YES,@"last_hash":previous,@"checkpoints":checkpoints};
        } else @throw @"unknown_operation";
    } @catch(id error) {answer=@{@"valid":@NO,@"error":[error description]};}
    puts([[NSString alloc] initWithData:canonical(answer) encoding:NSUTF8StringEncoding].UTF8String);
    return [answer[@"valid"] boolValue]?0:1;
}}
