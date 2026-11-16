#import "Observer.h"
#import <Security/Security.h>
#import <sys/stat.h>

NSString *AOProtectedDataDirectory(void) {
#ifdef AO_TEST_BUILD
    if(getenv("AO_TEST_DATA"))return @(getenv("AO_TEST_DATA"));
#endif
    return @"/Library/Application Support/ActivityObserver/data";
}
NSString *AOProtectedExecutable(void) {
#ifdef AO_TEST_BUILD
    if(getenv("AO_TEST_BINARY"))return @(getenv("AO_TEST_BINARY"));
#endif
    return @"/Library/PrivilegedHelperTools/local.activity-observer";
}
NSString *AODefaultDataDirectory(void) {
    NSString *protected=AOProtectedDataDirectory();
    if([NSFileManager.defaultManager fileExistsAtPath:protected]) return protected;
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Application Support/ActivityObserver/data"];
}
NSString *AOPublicKeyFile(NSString *directory) {
    if([directory.stringByStandardizingPath isEqual:AOProtectedDataDirectory().stringByStandardizingPath])return [directory.stringByDeletingLastPathComponent stringByAppendingPathComponent:@"public-key.der"];
    return [directory stringByAppendingPathComponent:@"public-key.der"];
}
NSString *AOEventHash(NSDictionary *row,NSString *previous) {
    NSMutableDictionary *payload=[NSMutableDictionary new];
    for(NSString *key in @[@"id",@"first",@"last",@"day",@"kind",@"app",@"pid",@"path",@"source",@"detail",@"priority",@"count"]) payload[key]=row[key] ?: NSNull.null;
    NSString *message=[NSString stringWithFormat:@"ActivityObserver-event-v1\n%@\n%@",previous,AOJSON(payload)];
    return AOHash([message dataUsingEncoding:NSUTF8StringEncoding]);
}

@implementation AOIntegrity {
    SecKeyRef _key;
}
- (instancetype)initWithPrivateDirectory:(NSString *)directory publicFile:(NSString *)publicFile create:(BOOL)create {
    if(!(self=[super init])) return nil;
    NSString *path=[directory stringByAppendingPathComponent:@"signing-key.der"];
    if(geteuid()==0){
        struct stat existing;
        if(lstat(path.fileSystemRepresentation,&existing)==0 && (existing.st_uid!=0||!S_ISREG(existing.st_mode)||(existing.st_mode&0077)))
            @throw [NSException exceptionWithName:@"IntegrityKey" reason:@"Signing key must be a private root-owned regular file" userInfo:nil];
        if(lstat(directory.fileSystemRepresentation,&existing)==0 && (existing.st_uid!=0||!S_ISDIR(existing.st_mode)||(existing.st_mode&0077)))
            @throw [NSException exceptionWithName:@"IntegrityKey" reason:@"Signing-key directory must be private and root-owned" userInfo:nil];
    }
    NSDictionary *attributes=@{(__bridge NSString *)kSecAttrKeyType:(__bridge NSString *)kSecAttrKeyTypeECSECPrimeRandom,(__bridge NSString *)kSecAttrKeyClass:(__bridge NSString *)kSecAttrKeyClassPrivate,(__bridge NSString *)kSecAttrKeySizeInBits:@256};
    NSData *saved=[NSData dataWithContentsOfFile:path]; CFErrorRef error=NULL;
    if(saved) _key=SecKeyCreateWithData((__bridge CFDataRef)saved,(__bridge CFDictionaryRef)attributes,&error);
    else if(create && ![NSFileManager.defaultManager fileExistsAtPath:publicFile]) {
        [NSFileManager.defaultManager createDirectoryAtPath:directory withIntermediateDirectories:YES attributes:@{NSFilePosixPermissions:@0700} error:nil];
        chmod(directory.fileSystemRepresentation,0700);
        _key=SecKeyCreateRandomKey((__bridge CFDictionaryRef)attributes,&error);
        if(_key) {
            NSData *private=CFBridgingRelease(SecKeyCopyExternalRepresentation(_key,&error));
            if(![private writeToFile:path options:NSDataWritingAtomic error:nil]) { CFRelease(_key);_key=NULL; }
            chmod(path.fileSystemRepresentation,0600);
        }
    }
    if(!_key) {
        NSString *reason=error ? [(__bridge NSError *)error localizedDescription] : @"Signing key missing; refusing to silently replace an existing identity";
        if(error) CFRelease(error);
        @throw [NSException exceptionWithName:@"IntegrityKey" reason:reason userInfo:nil];
    }
    if(error) CFRelease(error);
    SecKeyRef public=SecKeyCopyPublicKey(_key);
    NSData *bytes=CFBridgingRelease(SecKeyCopyExternalRepresentation(public,NULL)); CFRelease(public);
    _fingerprint=AOHash(bytes);
    NSData *existing=[NSData dataWithContentsOfFile:publicFile];
    if(existing && ![existing isEqual:bytes]) @throw [NSException exceptionWithName:@"IntegrityKey" reason:@"Public/private signing identities do not match" userInfo:nil];
    if(!existing) { [bytes writeToFile:publicFile options:NSDataWritingAtomic error:nil]; chmod(publicFile.fileSystemRepresentation,0644); }
    return self;
}
- (NSDictionary *)sign:(NSDictionary *)payload {
    NSData *message=[AOJSON(payload) dataUsingEncoding:NSUTF8StringEncoding]; CFErrorRef error=NULL;
    NSData *signature=CFBridgingRelease(SecKeyCreateSignature(_key,kSecKeyAlgorithmECDSASignatureMessageX962SHA256,(__bridge CFDataRef)message,&error));
    if(!signature) {
        NSString *reason=error?[(__bridge NSError *)error localizedDescription]:@"Signing failed";
        if(error) CFRelease(error);
        @throw [NSException exceptionWithName:@"IntegritySignature" reason:reason userInfo:nil];
    }
    if(error) CFRelease(error);
    return @{@"algorithm":@"ECDSA-P256-SHA256",@"key_fingerprint":_fingerprint,@"payload":payload,@"signature":[signature base64EncodedStringWithOptions:0]};
}
+ (BOOL)verify:(NSDictionary *)envelope publicFile:(NSString *)file expectedFingerprint:(NSString *)expected error:(NSString **)error {
    if(![envelope[@"algorithm"] isEqual:@"ECDSA-P256-SHA256"]){if(error)*error=@"Unsupported signature algorithm";return NO;}
    NSData *public=[NSData dataWithContentsOfFile:file];
    NSString *fingerprint=public?AOHash(public):@"";
    if(!public || ![fingerprint isEqual:envelope[@"key_fingerprint"]] || (expected.length&&![fingerprint isEqual:expected])) { if(error)*error=@"Public key fingerprint mismatch"; return NO; }
    if(![envelope[@"payload"] isKindOfClass:NSDictionary.class]||![envelope[@"signature"] isKindOfClass:NSString.class]) { if(error)*error=@"Invalid signed envelope";return NO; }
    NSDictionary *attributes=@{(__bridge NSString *)kSecAttrKeyType:(__bridge NSString *)kSecAttrKeyTypeECSECPrimeRandom,(__bridge NSString *)kSecAttrKeyClass:(__bridge NSString *)kSecAttrKeyClassPublic,(__bridge NSString *)kSecAttrKeySizeInBits:@256};
    SecKeyRef key=SecKeyCreateWithData((__bridge CFDataRef)public,(__bridge CFDictionaryRef)attributes,NULL); if(!key) { if(error)*error=@"Invalid public key";return NO; }
    NSData *signature=[[NSData alloc] initWithBase64EncodedString:envelope[@"signature"] options:0];
    NSData *message=[AOJSON(envelope[@"payload"]) dataUsingEncoding:NSUTF8StringEncoding];
    BOOL valid=signature&&SecKeyVerifySignature(key,kSecKeyAlgorithmECDSASignatureMessageX962SHA256,(__bridge CFDataRef)message,(__bridge CFDataRef)signature,NULL);
    CFRelease(key); if(!valid&&error)*error=@"Signature verification failed";return valid;
}
- (void)dealloc { if(_key) CFRelease(_key); }
@end
