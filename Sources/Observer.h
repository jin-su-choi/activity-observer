#import <Foundation/Foundation.h>
#import <sqlite3.h>

NS_ASSUME_NONNULL_BEGIN
static const uint64_t AODefaultMaxDataBytes = 1000000000ULL;
#define AO_VERSION "0.4.0"
static const NSUInteger AOReadRequestMaxBytes = 512 * 1024;
static const NSUInteger AOSensorFrameMaxBytes = 64 * 1024;
extern dispatch_queue_t ObserverQueue;
NSString *AOJSON(id object);
NSString *AODay(NSTimeInterval time);
NSString *AOTimeZoneName(void);
NSString *AOHash(NSData *data);
NSDictionary *AOProcess(pid_t pid);
NSDictionary *AOApp(NSString *path);
NSDictionary *AOReadPlist(NSString *path);
uint64_t AODirectoryBytes(NSString *path);
NSString *AODefaultDataDirectory(void);
NSString *AOProtectedDataDirectory(void);
NSString *AOProtectedExecutable(void);
NSString *AOPublicKeyFile(NSString *directory);

@interface AOIntegrity : NSObject
@property(nonatomic, readonly) NSString *fingerprint;
- (instancetype)initWithPrivateDirectory:(NSString *)directory publicFile:(NSString *)publicFile create:(BOOL)create;
- (NSDictionary *)sign:(NSDictionary *)payload;
+ (BOOL)verify:(NSDictionary *)envelope publicFile:(NSString *)file expectedFingerprint:(nullable NSString *)expected error:(NSString * _Nullable * _Nullable)error;
@end
NSString *AOEventHash(NSDictionary *row, NSString *previous);

@interface AOStore : NSObject
@property(nonatomic, readonly) NSString *directory;
@property(nonatomic, readonly) NSString *databasePath;
@property(nonatomic) NSMutableDictionary *health;
@property(nonatomic) uint64_t maxBytes;
@property(nonatomic) uint64_t dropped;
@property(nonatomic) uint64_t received;
@property(nonatomic) uint64_t written;
@property(nonatomic) uint64_t pruned;
@property(nonatomic) uint64_t prunedStatistics;
@property(nonatomic) NSTimeInterval started;
- (instancetype)initWithDirectory:(NSString *)directory maxBytes:(uint64_t)maxBytes;
- (instancetype)initWithDirectory:(NSString *)directory maxBytes:(uint64_t)maxBytes readOnly:(BOOL)readOnly;
- (void)record:(NSString *)kind actor:(NSDictionary *)actor source:(NSString *)source
       detail:(NSDictionary *)detail priority:(NSInteger)priority;
- (void)record:(NSString *)kind actor:(NSDictionary *)actor source:(NSString *)source
       detail:(NSDictionary *)detail priority:(NSInteger)priority at:(NSTimeInterval)time;
// Records observations that a sensor has already merged: their number and the
// times of the first and the last one.
- (void)record:(NSString *)kind actor:(NSDictionary *)actor source:(NSString *)source
       detail:(NSDictionary *)detail priority:(NSInteger)priority first:(NSTimeInterval)first
         last:(NSTimeInterval)last count:(long long)count;
- (void)setSensor:(NSString *)name status:(NSString *)status detail:(NSString *)detail;
- (void)flush;
- (void)maintain;
- (void)writeStatus;
- (NSArray *)query:(NSString *)sql arguments:(NSArray *)arguments;
- (BOOL)execute:(NSString *)sql arguments:(NSArray *)arguments;
- (NSDictionary *)reportSinceCheckpoint:(BOOL)since day:(nullable NSString *)day;
- (NSDictionary *)reportAfterID:(int64_t)after day:(nullable NSString *)day;
- (BOOL)checkpoint:(int64_t)through;
- (void)enableIntegrity:(AOIntegrity *)integrity;
- (NSDictionary *)verifyIntegrity:(nullable NSString *)expectedFingerprint;
- (NSDictionary *)verifyIntegrity:(nullable NSString *)expectedFingerprint live:(BOOL)live;
- (NSDictionary *)verifyIntegrity:(nullable NSString *)expectedFingerprint live:(BOOL)live readQueue:(nullable dispatch_queue_t)queue;
- (NSDictionary *)signedCheckpoint;
- (NSDictionary *)signedSnapshot;
- (NSDictionary *)activityQuery:(NSDictionary *)request;
- (void)close;
@end

@interface AOAgentStore : AOStore
- (instancetype)initWithProtectedDirectory:(NSString *)directory;
- (void)readCaptureStream:(void (^)(NSData *))consume;
@end
int AORunGuard(NSString *directory,uid_t user,NSString *executable);
NSDictionary *AORequestGuard(NSDictionary *request);

@interface AOCollector : NSObject
- (instancetype)initWithStore:(AOStore *)store roots:(NSArray<NSString *> *)roots;
- (void)start;
- (void)stop;
@end

BOOL AONetworkStart(void (^handler)(NSString *, NSDictionary *, NSDictionary *));
BOOL AOInternetSocketsBlocked(void);
void AONetworkQuery(void);
void AONetworkStop(void);
NS_ASSUME_NONNULL_END
