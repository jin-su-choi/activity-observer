#import "Observer.h"
#import <Security/Security.h>
#import <sys/socket.h>
#import <sys/un.h>
#import <sys/stat.h>
#import <sys/resource.h>
#import <sys/acl.h>
#import <sys/ucred.h>
#import <mach/mach.h>
#import <libproc.h>
#import <pwd.h>
#import <fcntl.h>
#import <signal.h>
#import <membership.h>
#import <sys/file.h>

static const char *guardSocketPath(void) {
#ifdef AO_TEST_BUILD
    if(getenv("AO_TEST_SOCKET"))return getenv("AO_TEST_SOCKET");
#endif
    return "/var/run/local.activity-observer.sock";
}
static uid_t protectedOwner(void) {
#ifdef AO_TEST_BUILD
    return geteuid();
#else
    return 0;
#endif
}
static void readACL(NSString *path,NSString *user,BOOL directory) {
    struct passwd *pw=getpwnam(user.UTF8String);uuid_t uuid;
    acl_t acl=acl_init(1);acl_entry_t entry;acl_permset_t permissions;acl_flagset_t flags;
    BOOL ok=pw && mbr_uid_to_uuid(pw->pw_uid,uuid)==0 && acl && acl_create_entry(&acl,&entry)==0 && acl_set_tag_type(entry,ACL_EXTENDED_ALLOW)==0 && acl_set_qualifier(entry,uuid)==0 && acl_get_permset(entry,&permissions)==0;
    if(ok){
        acl_clear_perms(permissions);acl_add_perm(permissions,ACL_READ_DATA);acl_add_perm(permissions,ACL_READ_ATTRIBUTES);acl_add_perm(permissions,ACL_READ_EXTATTRIBUTES);acl_add_perm(permissions,ACL_READ_SECURITY);
        if(directory)acl_add_perm(permissions,ACL_EXECUTE);
        ok=acl_set_permset(entry,permissions)==0;
        if(directory&&ok){ok=acl_get_flagset_np(entry,&flags)==0;if(ok){acl_add_flag_np(flags,ACL_ENTRY_FILE_INHERIT);acl_add_flag_np(flags,ACL_ENTRY_DIRECTORY_INHERIT);ok=acl_set_flagset_np(entry,flags)==0;}}
    }
    if(!ok || acl_set_file(path.fileSystemRepresentation,ACL_TYPE_EXTENDED,acl)!=0) {
        if(acl)acl_free(acl);
        @throw [NSException exceptionWithName:@"Permissions" reason:[NSString stringWithFormat:@"Could not grant read-only access to %@: %s",path,strerror(errno)] userInfo:nil];
    }
    acl_free(acl);
}
static int connectGuard(void) {
    int fd=socket(AF_UNIX,SOCK_STREAM,0);if(fd<0)return -1;
    fcntl(fd,F_SETFD,FD_CLOEXEC);
    struct sockaddr_un address={0};address.sun_family=AF_UNIX;strlcpy(address.sun_path,guardSocketPath(),sizeof(address.sun_path));
    if(connect(fd,(struct sockaddr *)&address,sizeof(address))!=0){close(fd);return -1;}
    uid_t peer;gid_t group;
    if(getpeereid(fd,&peer,&group)!=0||peer!=protectedOwner()){close(fd);return -1;}
    int one=1;setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one));return fd;
}
NSDictionary *AORequestGuard(NSDictionary *request) {
    int fd=connectGuard();if(fd<0)return @{@"error":@"protected_writer_unavailable"};
    // Full verification walks the retained event chain before returning a reply.
    struct timeval receiveTimeout={[request[@"op"] isEqual:@"verify"] ? 120 : 10,0};
    struct timeval sendTimeout={10,0};
    setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&receiveTimeout,sizeof(receiveTimeout));
    setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&sendTimeout,sizeof(sendTimeout));
    NSData *message=[[AOJSON(request) stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding];
    const uint8_t *bytes=message.bytes;NSUInteger offset=0;
    while(offset<message.length){ssize_t n=write(fd,bytes+offset,message.length-offset);if(n<=0){close(fd);return @{@"error":@"request_failed"};}offset+=(NSUInteger)n;}
    NSMutableData *response=[NSMutableData new];uint8_t buffer[8192];
    while(response.length<8*1024*1024){ssize_t n=read(fd,buffer,sizeof(buffer));if(n<=0)break;[response appendBytes:buffer length:(NSUInteger)n];if(memchr(buffer,'\n',(size_t)n))break;}
    close(fd);
    id result=[NSJSONSerialization JSONObjectWithData:response options:0 error:nil];return [result isKindOfClass:NSDictionary.class]?result:@{@"error":@"invalid_guard_response"};
}

@implementation AOAgentStore {
    int _socket;
    NSMutableData *_outgoing;
    dispatch_source_t _writeSource;
    dispatch_source_t _captureSource;
    BOOL _writeResumed;
    BOOL _connected;
    NSTimeInterval _cpuTime;
    double _cpuTotal;
    double _cpuPercent;
    NSString *_protectedDirectory;
    NSMutableDictionary *_inventoryCache;
    BOOL _baselineComplete;
    uint64_t _sequence;
}
- (instancetype)initWithProtectedDirectory:(NSString *)directory {
    self=[super init];if(!self)return nil;
    _protectedDirectory=directory;self.started=NSDate.date.timeIntervalSince1970;self.health=[NSMutableDictionary new];
    _inventoryCache=[NSMutableDictionary new];NSString *cursor=@"";
    while(YES){@autoreleasepool{
        NSDictionary *snapshot=AORequestGuard(@{@"op":@"inventory",@"after_path":cursor});
        if(snapshot[@"error"]||![snapshot[@"inventory"] isKindOfClass:NSArray.class])@throw [NSException exceptionWithName:@"GuardConnection" reason:AOJSON(snapshot) userInfo:nil];
        for(NSDictionary *row in snapshot[@"inventory"])if(row[@"path"])_inventoryCache[row[@"path"]]=row;
        _baselineComplete=[snapshot[@"baseline_complete"] boolValue];
        NSString *next=snapshot[@"next_path"];
        if(!next.length)break;
        if([next isEqual:cursor])@throw [NSException exceptionWithName:@"GuardConnection" reason:@"Inventory pagination did not advance" userInfo:nil];
        cursor=next;
    }}
    _socket=connectGuard();if(_socket<0)@throw [NSException exceptionWithName:@"GuardConnection" reason:@"Protected writer unavailable" userInfo:nil];
    _outgoing=[NSMutableData new];fcntl(_socket,F_SETFL,fcntl(_socket,F_GETFL)|O_NONBLOCK);
    __weak AOAgentStore *weak=self;
    _writeSource=dispatch_source_create(DISPATCH_SOURCE_TYPE_WRITE,_socket,0,ObserverQueue);
    dispatch_source_set_event_handler(_writeSource,^{[weak drain];});
    _connected=YES;
    [self send:@{@"op":@"hello",@"pid":@(getpid())}];return self;
}
- (NSString *)directory{return _protectedDirectory;}
- (NSString *)databasePath{return [_protectedDirectory stringByAppendingPathComponent:@"events.sqlite"];}
- (NSArray *)query:(NSString *)sql arguments:(NSArray *)arguments {
    if([sql isEqual:@"SELECT 1 FROM state WHERE key='baseline_complete'"])return _baselineComplete?@[@{@"1":@1}]:@[];
    if([sql isEqual:@"SELECT path,detail FROM inventory"])return _inventoryCache.allValues;
    if([sql isEqual:@"SELECT fingerprint,detail FROM inventory WHERE path=?"]||[sql isEqual:@"SELECT 1 FROM inventory WHERE path=?"]){NSDictionary *row=arguments.count?_inventoryCache[arguments[0]]:nil;return row?@[row]:@[];}
    return @[];
}
- (void)send:(NSDictionary *)message {
    if(!_connected)return;
    NSMutableDictionary *framed=[message mutableCopy];framed[@"sequence"]=@(++_sequence);
    NSData *data=[[AOJSON(framed) stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding];
    if(data.length>AOSensorFrameMaxBytes || _outgoing.length+data.length>1024*1024){self.dropped++;return;}
    [_outgoing appendData:data];[self drain];
    if(_outgoing.length&&!_writeResumed){_writeResumed=YES;dispatch_resume(_writeSource);}
}
- (void)drain {
    while(_outgoing.length){
        ssize_t n=write(_socket,_outgoing.bytes,_outgoing.length);
        if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK))break;
        if(n<=0){_connected=NO;_exit(75);}
        [_outgoing replaceBytesInRange:NSMakeRange(0,(NSUInteger)n) withBytes:NULL length:0];
    }
    if(!_outgoing.length&&_writeResumed){_writeResumed=NO;dispatch_suspend(_writeSource);}
}
- (void)record:(NSString *)kind actor:(NSDictionary *)actor source:(NSString *)source detail:(NSDictionary *)detail priority:(NSInteger)priority {
    [self record:kind actor:actor source:source detail:detail priority:priority at:NSDate.date.timeIntervalSince1970];
}
- (void)record:(NSString *)kind actor:(NSDictionary *)actor source:(NSString *)source detail:(NSDictionary *)detail priority:(NSInteger)priority at:(NSTimeInterval)time {
    self.received++;
    [self send:@{@"op":@"event",@"kind":kind,@"actor":actor,@"source":source,@"detail":detail,@"priority":@(priority),@"time":@(time)}];
}
- (void)record:(NSString *)kind actor:(NSDictionary *)actor source:(NSString *)source detail:(NSDictionary *)detail priority:(NSInteger)priority first:(NSTimeInterval)first last:(NSTimeInterval)time count:(long long)count {
    self.received+=(uint64_t)MAX(count,1);
    [self send:@{@"op":@"event",@"kind":kind,@"actor":actor,@"source":source,@"detail":detail,@"priority":@(priority),@"time":@(time),@"first":@(first),@"count":@(MAX(count,1))}];
}
- (BOOL)execute:(NSString *)sql arguments:(NSArray *)arguments {
    if(!_connected)return [super execute:sql arguments:arguments];
    if([@[@"BEGIN IMMEDIATE",@"COMMIT",@"ROLLBACK"] containsObject:sql])return YES;
    if([sql hasPrefix:@"INSERT INTO inventory("]&&arguments.count==4)_inventoryCache[arguments[0]]=@{@"path":arguments[0],@"fingerprint":arguments[1],@"detail":arguments[2]};
    if([sql isEqual:@"DELETE FROM inventory WHERE path=?"]&&arguments.count==1)[_inventoryCache removeObjectForKey:arguments[0]];
    if([sql containsString:@"VALUES('baseline_complete','1')"])_baselineComplete=YES;
    [self send:@{@"op":@"inventory_sql",@"sql":sql,@"arguments":arguments}];return YES;
}
- (void)setSensor:(NSString *)name status:(NSString *)status detail:(NSString *)detail {
    [self send:@{@"op":@"sensor",@"name":name,@"status":status,@"detail":detail}];
}
- (void)flush { [self send:@{@"op":@"flush"}]; }
- (void)maintain { [self writeStatus]; }
- (void)writeStatus {
    struct rusage r={0};getrusage(RUSAGE_SELF,&r);double cpu=r.ru_utime.tv_sec+r.ru_utime.tv_usec/1e6+r.ru_stime.tv_sec+r.ru_stime.tv_usec/1e6;
    NSTimeInterval now=NSDate.date.timeIntervalSince1970;
    if(!_cpuTime){_cpuTime=now;_cpuTotal=cpu;}else if(now-_cpuTime>=5){_cpuPercent=MAX(0,(cpu-_cpuTotal)/(now-_cpuTime)*100);_cpuTime=now;_cpuTotal=cpu;}
    mach_task_basic_info_data_t info={0};mach_msg_type_number_t size=MACH_TASK_BASIC_INFO_COUNT;task_info(mach_task_self(),MACH_TASK_BASIC_INFO,(task_info_t)&info,&size);
    [self send:@{@"op":@"metrics",@"pid":@(getpid()),@"cpu_percent":@(_cpuPercent),@"resident_bytes":@(info.resident_size),@"dropped":@(self.dropped),@"received":@(self.received)}];
}
- (void)readCaptureStream:(void (^)(NSData *))consume {
    if(_captureSource||!_connected)return;
    int fd=_socket;
    _captureSource=dispatch_source_create(DISPATCH_SOURCE_TYPE_READ,fd,0,ObserverQueue);
    dispatch_source_set_event_handler(_captureSource,^{
        uint8_t bytes[8192];
        for(int i=0;i<16;i++) {
            ssize_t n=read(fd,bytes,sizeof(bytes));
            if(n>0){consume([NSData dataWithBytes:bytes length:(NSUInteger)n]);continue;}
            if(n==0||(errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR))_exit(75);
            break;
        }
    });
    dispatch_resume(_captureSource);
}
- (void)close {
    if(_connected){[self send:@{@"op":@"flush"}];_connected=NO;}
    if(_writeSource){if(!_writeResumed)dispatch_resume(_writeSource);dispatch_source_cancel(_writeSource);_writeSource=nil;}
    if(_captureSource){dispatch_source_cancel(_captureSource);_captureSource=nil;}
    if(_socket>=0){close(_socket);_socket=-1;}[super close];
}
@end

@interface AOGuard : NSObject
@property AOStore *store;
@property uid_t user;
@property NSString *userName;
@property NSString *executable;
@property pid_t agentPID;
@property int listener;
@property NSMutableDictionary *connections;
@property NSMutableArray *sources;
@property dispatch_source_t capturePipe;
@property NSTimeInterval lastAgentHeartbeat;
@property BOOL stopping;
@property NSUInteger capacityRejections;
@property NSUInteger authenticationRejections;
@property NSDictionary *snapshotCache;
@property NSTimeInterval lastSnapshot;
@property NSData *expectedCodeHash;
@property dispatch_queue_t verificationQueue;
@property BOOL verifying;
@end

@implementation AOGuard
- (BOOL)trustedPeer:(int)fd pid:(pid_t *)pidOut {
    uid_t uid;gid_t gid;pid_t pid=0;socklen_t size=sizeof(pid);
    if(getpeereid(fd,&uid,&gid)!=0 || uid!=_user || getsockopt(fd,SOL_LOCAL,LOCAL_PEERPID,&pid,&size)!=0)return NO;
    char path[PROC_PIDPATHINFO_MAXSIZE]={0};if(proc_pidpath(pid,path,sizeof(path))<=0||![_executable isEqual:@(path)])return NO;
    struct stat st;if(lstat(path,&st)!=0||st.st_uid!=protectedOwner()||(st.st_mode&0022)||!S_ISREG(st.st_mode))return NO;
    SecCodeRef code=NULL;NSDictionary *attributes=@{(__bridge NSString *)kSecGuestAttributePid:@(pid)};
    BOOL valid=SecCodeCopyGuestWithAttributes(NULL,(__bridge CFDictionaryRef)attributes,kSecCSDefaultFlags,&code)==errSecSuccess;
    if(valid)valid=SecCodeCheckValidity(code,kSecCSStrictValidate,NULL)==errSecSuccess;
    CFDictionaryRef info=NULL;
    if(valid && SecCodeCopySigningInformation(code,kSecCSSigningInformation,&info)==errSecSuccess){
        NSDictionary *signing=CFBridgingRelease(info);
        valid=([signing[(__bridge NSString *)kSecCodeInfoFlags] unsignedIntValue]&kSecCodeSignatureRuntime)!=0 && [signing[(__bridge NSString *)kSecCodeInfoUnique] isEqual:_expectedCodeHash];
    }else valid=NO;
    if(code)CFRelease(code);if(valid)*pidOut=pid;return valid;
}
- (void)accept {
    int fd;
    while((fd=accept(_listener,NULL,NULL))>=0){
        pid_t pid=0;
        if(_connections.count>=(_verifying?4:3)){close(fd);_capacityRejections++;continue;}
        if(![self trustedPeer:fd pid:&pid]){close(fd);_authenticationRejections++;continue;}
        int one=1;setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one));fcntl(fd,F_SETFL,fcntl(fd,F_GETFL)|O_NONBLOCK);
        fcntl(fd,F_SETFD,FD_CLOEXEC);
        NSMutableDictionary *connection=[@{@"pid":@(pid),@"buffer":[NSMutableData new],@"agent":@NO,@"last":@(NSDate.date.timeIntervalSince1970)} mutableCopy];
        NSNumber *key=@(fd);_connections[key]=connection;
        dispatch_source_t source=dispatch_source_create(DISPATCH_SOURCE_TYPE_READ,fd,0,ObserverQueue);connection[@"source"]=source;
        __weak AOGuard *weak=self;
        dispatch_source_set_event_handler(source,^{@autoreleasepool{[weak read:fd];}});dispatch_source_set_cancel_handler(source,^{close(fd);});dispatch_resume(source);
    }
}
- (void)disconnect:(int)fd {
    NSDictionary *c=_connections[@(fd)];if(!c)return;
    if([c[@"agent"] boolValue]){
        [_store record:@"sensor_connection_closed" actor:@{@"app":@"activity-observer",@"pid":c[@"pid"]} source:@"protected_writer" detail:@{@"expected_shutdown":@(_stopping),@"partial_frame_bytes":@([c[@"buffer"] length])} priority:_stopping?1:3];
        _agentPID=0;
    }
    if([c[@"read_suspended"] boolValue])dispatch_resume(c[@"source"]);
    if(c[@"write_source"])dispatch_source_cancel(c[@"write_source"]);
    if(c[@"capture_writer"])dispatch_source_cancel(c[@"capture_writer"]);
    dispatch_source_cancel(c[@"source"]);[_connections removeObjectForKey:@(fd)];
}
- (void)respond:(NSDictionary *)response fd:(int)fd {
    NSMutableDictionary *c=_connections[@(fd)];if(!c)return;
    NSData *data=[[AOJSON(response) stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding];
    if(data.length>8*1024*1024)data=[@"{\"error\":\"response_limit_exceeded_use_smaller_pages\"}\n" dataUsingEncoding:NSUTF8StringEncoding];
    c[@"response"]=data;c[@"offset"]=@0;c[@"read_suspended"]=@YES;dispatch_suspend(c[@"source"]);
    dispatch_source_t writer=dispatch_source_create(DISPATCH_SOURCE_TYPE_WRITE,fd,0,ObserverQueue);c[@"write_source"]=writer;
    __weak AOGuard *weak=self;dispatch_source_set_event_handler(writer,^{[weak writeResponse:fd];});dispatch_resume(writer);
}
- (void)writeResponse:(int)fd {
    NSMutableDictionary *c=_connections[@(fd)];if(!c)return;NSData *data=c[@"response"];NSUInteger offset=[c[@"offset"] unsignedIntegerValue];
    while(offset<data.length){ssize_t n=write(fd,(const uint8_t *)data.bytes+offset,data.length-offset);if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK)){c[@"offset"]=@(offset);return;}if(n<=0){[self disconnect:fd];return;}offset+=(NSUInteger)n;}
    [self disconnect:fd];
}
- (void)startVerification:(NSString *)expected fd:(int)fd {
    if(_verifying){[self respond:@{@"error":@"verification_busy"} fd:fd];return;}
    _verifying=YES;
    NSMutableDictionary *client=_connections[@(fd)];
    client[@"verifying"]=@YES;
    client[@"read_suspended"]=@YES;
    dispatch_suspend(client[@"source"]);
    dispatch_async(_verificationQueue,^{@autoreleasepool{
        NSDictionary *result;
        @try {
            result=[self.store verifyIntegrity:expected live:YES readQueue:ObserverQueue];
        } @catch(NSException *error) {
            result=@{@"error":@"verification_read_failed"};
        }
        dispatch_async(ObserverQueue,^{
            self.verifying=NO;
            if(self.connections[@(fd)]!=client) return;
            [client removeObjectForKey:@"verifying"];
            [client removeObjectForKey:@"read_suspended"];
            dispatch_resume(client[@"source"]);
            [self respond:result fd:fd];
        });
    }});
}
- (void)read:(int)fd {
    NSMutableDictionary *c=_connections[@(fd)];if(!c)return;
    uint8_t chunk[16384];ssize_t n;
    while((n=read(fd,chunk,sizeof(chunk)))>0){
        NSMutableData *buffer=c[@"buffer"];[buffer appendBytes:chunk length:(NSUInteger)n];
        if(buffer.length>1024*1024){[self disconnect:fd];return;}
        while(YES){
            const void *newline=memchr(buffer.bytes,'\n',buffer.length);if(!newline)break;
            NSUInteger length=(const char *)newline-(const char *)buffer.bytes;
            NSData *line=[buffer subdataWithRange:NSMakeRange(0,length)];[buffer replaceBytesInRange:NSMakeRange(0,length+1) withBytes:NULL length:0];
            if(length>([c[@"agent"] boolValue]?AOSensorFrameMaxBytes:AOReadRequestMaxBytes)){[self disconnect:fd];return;}
            NSDictionary *message=[NSJSONSerialization JSONObjectWithData:line options:0 error:nil];
            if(![message isKindOfClass:NSDictionary.class]){[self disconnect:fd];return;}
            c[@"last"]=@(NSDate.date.timeIntervalSince1970);[self handle:message fd:fd];
            if(!_connections[@(fd)])return;
            if([c[@"read_suspended"] boolValue])return;
        }
    }
    if(n==0 || (n<0&&errno!=EAGAIN&&errno!=EWOULDBLOCK))[self disconnect:fd];
}
- (void)handle:(NSDictionary *)m fd:(int)fd {
    NSMutableDictionary *connection=_connections[@(fd)];NSString *op=m[@"op"];
    if([op isEqual:@"inventory"]){
        NSString *after=[m[@"after_path"] isKindOfClass:NSString.class]?m[@"after_path"]:@"";
        NSArray *rows=[_store query:@"SELECT path,fingerprint,detail FROM inventory WHERE path>? ORDER BY path LIMIT 64" arguments:@[after]];
        [self respond:@{@"inventory":rows,@"next_path":rows.count==64?rows.lastObject[@"path"]:@"",@"baseline_complete":@([_store query:@"SELECT 1 FROM state WHERE key='baseline_complete'" arguments:@[]].count>0)} fd:fd];return;
    }
    if([op isEqual:@"status"]||[op isEqual:@"monitor-context"]){
        NSData *data=[NSData dataWithContentsOfFile:[_store.directory stringByAppendingPathComponent:@"status.json"]];
        NSDictionary *status=data?[NSJSONSerialization JSONObjectWithData:data options:0 error:nil]:nil;
        if(status && [op isEqual:@"monitor-context"]) {
            if(!_snapshotCache||NSDate.date.timeIntervalSince1970-_lastSnapshot>=60){
                _snapshotCache=[_store signedSnapshot];_lastSnapshot=NSDate.date.timeIntervalSince1970;
            }
            [self respond:@{@"status":status,@"anchor":_snapshotCache} fd:fd];return;
        }
        [self respond:status ?: @{@"error":@"status_not_ready"} fd:fd];return;
    }
    if([op isEqual:@"verify"]){
        NSString *expected=[m[@"expected_key"] isKindOfClass:NSString.class]?m[@"expected_key"]:nil;
        [self startVerification:expected fd:fd];return;
    }
    if([op isEqual:@"integrity-checkpoint"]){
        [self respond:[_store signedCheckpoint] fd:fd];return;
    }
    if([op isEqual:@"report"]){
        NSString *day=[m[@"day"] isKindOfClass:NSString.class]?m[@"day"]:nil;
        if(day.length&&![day rangeOfString:@"^[0-9]{4}-[0-9]{2}-[0-9]{2}$" options:NSRegularExpressionSearch].length){[self respond:@{@"error":@"invalid_day"} fd:fd];return;}
        int64_t after=[m[@"after"] isKindOfClass:NSNumber.class]?[m[@"after"] longLongValue]:0;
        [self respond:[_store reportAfterID:after day:day] fd:fd];return;
    }
    if([op isEqual:@"activity-query"]){[self respond:[_store activityQuery:m] fd:fd];return;}
    if([op isEqual:@"events"]){
        int64_t after=[m[@"after"] isKindOfClass:NSNumber.class]?[m[@"after"] longLongValue]:0;
        int64_t through=[m[@"through"] isKindOfClass:NSNumber.class]?[m[@"through"] longLongValue]:INT64_MAX;
        int limit=[m[@"limit"] isKindOfClass:NSNumber.class]?MAX(1,MIN(500,[m[@"limit"] intValue])):100;
        NSArray *rows=[_store query:@"SELECT * FROM events WHERE id>? AND id<=? ORDER BY id LIMIT ?" arguments:@[@(after),@(through),@(limit)]];
        [self respond:@{@"events":rows,@"next_after":rows.lastObject[@"id"] ?: @(after),@"through":@(through)} fd:fd];return;
    }
    if([op isEqual:@"snapshot"]){
        if([m[@"fresh"] isEqual:@YES]||!_snapshotCache||NSDate.date.timeIntervalSince1970-_lastSnapshot>=60){_snapshotCache=[_store signedSnapshot];_lastSnapshot=NSDate.date.timeIntervalSince1970;}
        [self respond:_snapshotCache fd:fd];return;
    }
    if([op isEqual:@"hello"]){
        if(_agentPID&&_agentPID!=[connection[@"pid"] intValue]){[self disconnect:fd];return;}
        _agentPID=[connection[@"pid"] intValue];connection[@"agent"]=@YES;connection[@"sequence"]=m[@"sequence"] ?: @0;_lastAgentHeartbeat=NSDate.date.timeIntervalSince1970;
        [_store record:@"sensor_connected" actor:AOProcess(_agentPID) source:@"protected_writer" detail:@{@"peer_code_verified":@YES} priority:2];return;
    }
    if(![connection[@"agent"] boolValue]){[self disconnect:fd];return;}
    uint64_t sequence=[m[@"sequence"] isKindOfClass:NSNumber.class]?[m[@"sequence"] unsignedLongLongValue]:0;
    uint64_t previous=[connection[@"sequence"] unsignedLongLongValue];
    if(sequence<=previous){[self disconnect:fd];return;}
    if(sequence!=previous+1)[_store record:@"sensor_transport_gap" actor:@{@"app":@"activity-observer",@"pid":connection[@"pid"]} source:@"protected_writer" detail:@{@"expected_sequence":@(previous+1),@"received_sequence":@(sequence)} priority:3];
    connection[@"sequence"]=@(sequence);
    if([op isEqual:@"event"]&&[m[@"kind"] isKindOfClass:NSString.class]&&[m[@"actor"] isKindOfClass:NSDictionary.class]&&[m[@"detail"] isKindOfClass:NSDictionary.class]&&[m[@"source"] isKindOfClass:NSString.class]){
        NSTimeInterval t=[m[@"time"] doubleValue],now=NSDate.date.timeIntervalSince1970;if(!isfinite(t)||t>now+30||t<now-86400)t=now;
        // A sensor may merge repeated observations before sending them.
        long long count=[m[@"count"] isKindOfClass:NSNumber.class]?MAX(1,MIN(1000000,[m[@"count"] longLongValue])):1;
        NSTimeInterval first=[m[@"first"] isKindOfClass:NSNumber.class]?[m[@"first"] doubleValue]:t;if(!isfinite(first)||first>t||first<t-3600)first=t;
        [_store record:m[@"kind"] actor:m[@"actor"] source:m[@"source"] detail:m[@"detail"] priority:MAX(0,MIN(3,[m[@"priority"] intValue])) first:first last:t count:count];
    }else if([op isEqual:@"sensor"]&&[m[@"name"] isKindOfClass:NSString.class]&&[m[@"status"] isKindOfClass:NSString.class]&&[m[@"detail"] isKindOfClass:NSString.class]){
        // Reserved writer-health fields cannot be replaced by the user sensor.
        if(![m[@"name"] hasPrefix:@"guard_"])[_store setSensor:m[@"name"] status:m[@"status"] detail:m[@"detail"]];
    }else if([op isEqual:@"metrics"]){
        _lastAgentHeartbeat=NSDate.date.timeIntervalSince1970;
        uint64_t drops=[m[@"dropped"] unsignedLongLongValue],old=[connection[@"agent_dropped"] unsignedLongLongValue];
        if(drops>old)_store.dropped+=drops-old;connection[@"agent_dropped"]=@(drops);
        _store.health[@"guard_sensor_metrics"]=@{@"status":@"active",@"pid":@(_agentPID),@"cpu_percent":m[@"cpu_percent"] ?: @0,@"resident_bytes":m[@"resident_bytes"] ?: @0,@"dropped":m[@"dropped"] ?: @0,@"checked_at":@(_lastAgentHeartbeat)};
    }else if([op isEqual:@"flush"]){[_store flush];}
    else if([op isEqual:@"inventory_sql"]&&[m[@"arguments"] isKindOfClass:NSArray.class]){
        NSDictionary *allowed=@{
          @"INSERT OR REPLACE INTO state(key,value) VALUES('baseline_complete','1')":@0,
          @"DELETE FROM inventory WHERE path=?":@1,
          @"INSERT INTO inventory(path,fingerprint,detail,updated) VALUES(?,?,?,?) ON CONFLICT(path) DO UPDATE SET fingerprint=excluded.fingerprint,detail=excluded.detail,updated=excluded.updated":@4};
        NSNumber *count=allowed[m[@"sql"]];NSArray *arguments=m[@"arguments"];
        if(count&&arguments.count==count.unsignedIntegerValue)[_store execute:m[@"sql"] arguments:arguments];
        else {[_store record:@"guard_protocol_rejected" actor:AOProcess(_agentPID) source:@"protected_writer" detail:@{@"operation":@"inventory_sql"} priority:3];[self disconnect:fd];}
    }else {[_store record:@"guard_protocol_rejected" actor:AOProcess(_agentPID) source:@"protected_writer" detail:@{@"operation":[op isKindOfClass:NSString.class]?op:@"invalid"} priority:3];[self disconnect:fd];}
}
- (void)recordRejections {
    if(!_capacityRejections&&!_authenticationRejections)return;
    NSDictionary *counts=@{@"connection_limit":@(_capacityRejections),@"peer_authentication_failed":@(_authenticationRejections)};
    for(NSString *reason in counts) {
        if([counts[reason] unsignedIntegerValue])
            [_store record:@"guard_connection_rejected" actor:@{@"app":@"protected-writer"} source:@"protected_writer"
                    detail:@{@"reason":reason,@"count":counts[reason]} priority:3];
    }
    _capacityRejections=0;_authenticationRejections=0;
}
- (void)drainCapture:(int)fd {
    NSMutableDictionary *connection=_connections[@(fd)];
    NSMutableData *buffer=connection[@"capture_buffer"];
    while(buffer.length) {
        ssize_t n=write(fd,buffer.bytes,buffer.length);
        if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK))return;
        if(n<=0){[self disconnect:fd];return;}
        [buffer replaceBytesInRange:NSMakeRange(0,(NSUInteger)n) withBytes:NULL length:0];
    }
    dispatch_source_t writer=connection[@"capture_writer"];
    if(writer){dispatch_source_cancel(writer);[connection removeObjectForKey:@"capture_writer"];}
}
- (void)forwardCapture:(NSData *)data {
    for(NSNumber *fd in _connections.allKeys) {
        NSMutableDictionary *connection=_connections[fd];
        if(![connection[@"agent"] boolValue])continue;
        NSMutableData *buffer=connection[@"capture_buffer"];
        if(!buffer){buffer=[NSMutableData new];connection[@"capture_buffer"]=buffer;}
        if(buffer.length+data.length>1024*1024) {
            [_store record:@"collection_gap" actor:@{@"app":@"activity-observer"} source:@"unified_log"
                    detail:@{@"reason":@"Capture stream queue exceeded its limit"} priority:3];
            [self disconnect:fd.intValue];
            return;
        }
        [buffer appendData:data];
        [self drainCapture:fd.intValue];
        if(_connections[fd]&&buffer.length&&!connection[@"capture_writer"]) {
            dispatch_source_t writer=dispatch_source_create(DISPATCH_SOURCE_TYPE_WRITE,fd.intValue,0,ObserverQueue);
            connection[@"capture_writer"]=writer;
            __weak AOGuard *weak=self;
            dispatch_source_set_event_handler(writer,^{[weak drainCapture:fd.intValue];});
            dispatch_resume(writer);
        }
        return;
    }
}
- (void)startCapturePipe {
    if(_capturePipe||_stopping)return;
    const char *path="/Library/Application Support/ActivityObserver/capture.fifo";
#ifdef AO_TEST_BUILD
    if(getenv("AO_TEST_CAPTURE_FIFO"))path=getenv("AO_TEST_CAPTURE_FIFO");
#endif
    int fd=open(path,O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC);
    struct stat info;
    if(fd<0||fstat(fd,&info)!=0||!S_ISFIFO(info.st_mode)||info.st_uid!=protectedOwner()||(info.st_mode&0077)) {
        if(fd>=0)close(fd);
        [_store setSensor:@"guard_capture_feed" status:@"unavailable" detail:@"Root-owned capture stream pipe is unavailable"];
        return;
    }
    _capturePipe=dispatch_source_create(DISPATCH_SOURCE_TYPE_READ,fd,0,ObserverQueue);
    __weak AOGuard *weak=self;
    dispatch_source_set_event_handler(_capturePipe,^{
        AOGuard *guard=weak;
        if(!guard)return;
        uint8_t bytes[8192];
        for(int i=0;i<16;i++) {
            ssize_t n=read(fd,bytes,sizeof(bytes));
            if(n>0){[guard forwardCapture:[NSData dataWithBytes:bytes length:(NSUInteger)n]];continue;}
            if(n==0||(errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR)) {
                dispatch_source_cancel(guard.capturePipe);
                guard.capturePipe=nil;
                [guard.store setSensor:@"guard_capture_feed" status:@"unavailable" detail:@"System log reader stopped; reconnecting"];
            }
            break;
        }
    });
    dispatch_source_set_cancel_handler(_capturePipe,^{close(fd);});
    dispatch_resume(_capturePipe);
    [_store setSensor:@"guard_capture_feed" status:@"active" detail:@"Root-only one-way capture feed to the authenticated sensor"];
}
- (void)tick {
    for(NSNumber *fd in [_connections.allKeys copy]){
        NSDictionary *c=_connections[fd];
        if(NSDate.date.timeIntervalSince1970-[c[@"last"] doubleValue]>40 && ![c[@"agent"] boolValue] && ![c[@"verifying"] boolValue])[self disconnect:fd.intValue];
    }
    if(_agentPID&&NSDate.date.timeIntervalSince1970-_lastAgentHeartbeat>45){
        [_store record:@"sensor_heartbeat_missing" actor:@{@"app":@"activity-observer",@"pid":@(_agentPID)} source:@"protected_writer" detail:@{} priority:3];
        char path[PROC_PIDPATHINFO_MAXSIZE]={0};proc_pidpath(_agentPID,path,sizeof(path));if([_executable isEqual:@(path)])kill(_agentPID,SIGKILL);
    }
    [self recordRejections];
    [self startCapturePipe];
    [_store setSensor:@"guard_session" status:_agentPID?@"active":@"waiting" detail:@"GUI-session sensor is managed by its own launchd job"];
    [_store setSensor:@"guard_sensor_liveness" status:_agentPID&&NSDate.date.timeIntervalSince1970-_lastAgentHeartbeat<35?@"active":@"waiting" detail:_agentPID?@"Authenticated sensor heartbeat tracked":@"Waiting for an authenticated sensor connection"];
    [_store flush];[_store writeStatus];
}
- (void)stop {
    _stopping=YES;if(_agentPID)kill(_agentPID,SIGTERM);
    if(_capturePipe){dispatch_source_cancel(_capturePipe);_capturePipe=nil;}
    for(NSNumber *fd in [_connections.allKeys copy])[self disconnect:fd.intValue];
    [self recordRejections];
    [_store record:@"guard_stopped" actor:AOProcess(getpid()) source:@"protected_writer" detail:@{} priority:2];[_store flush];[_store writeStatus];[_store close];unlink(guardSocketPath());exit(0);
}
@end

int AORunGuard(NSString *directory,uid_t user,NSString *executable) {
    if(geteuid()!=protectedOwner()||user==0){puts("Protected writer requires root and a non-root target user.");return 77;}
    if(!AOInternetSocketsBlocked()){puts("Protected writer requires its network isolation policy.");return 77;}
    struct passwd *pw=getpwuid(user);if(!pw)return 77;NSString *name=@(pw->pw_name);gid_t userGroup=pw->pw_gid;
    struct stat binary;if(lstat(executable.fileSystemRepresentation,&binary)!=0||binary.st_uid!=protectedOwner()||(binary.st_mode&0022)||!S_ISREG(binary.st_mode)){puts("Refusing a writable or non-root-owned executable.");return 77;}
    ObserverQueue=dispatch_queue_create("local.activity-observer.guard",dispatch_queue_attr_make_with_autorelease_frequency(dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL,QOS_CLASS_UTILITY,0),DISPATCH_AUTORELEASE_FREQUENCY_WORK_ITEM));
    AOGuard *guard=[AOGuard new];guard.user=user;guard.userName=name;guard.executable=executable;guard.connections=[NSMutableDictionary new];guard.sources=[NSMutableArray new];
    guard.verificationQueue=dispatch_queue_create("local.activity-observer.verify",dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL,QOS_CLASS_UTILITY,0));
    @try {
        umask(0077);
        SecStaticCodeRef installed=NULL;CFDictionaryRef info=NULL;
        if(SecStaticCodeCreateWithPath((__bridge CFURLRef)[NSURL fileURLWithPath:executable],kSecCSDefaultFlags,&installed)!=errSecSuccess||SecCodeCopySigningInformation(installed,kSecCSSigningInformation,&info)!=errSecSuccess)@throw [NSException exceptionWithName:@"CodeIdentity" reason:@"Could not verify installed executable identity" userInfo:nil];
        NSDictionary *signing=CFBridgingRelease(info);guard.expectedCodeHash=signing[(__bridge NSString *)kSecCodeInfoUnique];CFRelease(installed);
        if(!guard.expectedCodeHash)@throw [NSException exceptionWithName:@"CodeIdentity" reason:@"Installed executable has no code-directory hash" userInfo:nil];
        [NSFileManager.defaultManager createDirectoryAtPath:directory withIntermediateDirectories:YES attributes:@{NSFilePosixPermissions:@0700} error:nil];chmod(directory.fileSystemRepresentation,0700);
        int lock=open([directory stringByAppendingPathComponent:@"guard.lock"].fileSystemRepresentation,O_CREAT|O_RDWR|O_NOFOLLOW|O_CLOEXEC,0600);
        if(lock<0||flock(lock,LOCK_EX|LOCK_NB)!=0){puts("Protected writer is already running.");return 77;}
        struct stat dbInfo;NSString *dbPath=[directory stringByAppendingPathComponent:@"events.sqlite"];
        if(lstat(dbPath.fileSystemRepresentation,&dbInfo)==0&&(dbInfo.st_uid!=protectedOwner()||!S_ISREG(dbInfo.st_mode)||(dbInfo.st_mode&0022)))@throw [NSException exceptionWithName:@"Permissions" reason:@"Refusing a database not exclusively writable by root" userInfo:nil];
        guard.store=[[AOStore alloc] initWithDirectory:directory maxBytes:AODefaultMaxDataBytes];
        if(![NSFileManager.defaultManager fileExistsAtPath:AOPublicKeyFile(directory)])@throw [NSException exceptionWithName:@"IntegrityKey" reason:@"Public verification key must be provisioned by the installer" userInfo:nil];
        AOIntegrity *integrity=[[AOIntegrity alloc] initWithPrivateDirectory:[directory.stringByDeletingLastPathComponent stringByAppendingPathComponent:@"private"] publicFile:AOPublicKeyFile(directory) create:NO];
        [guard.store enableIntegrity:integrity];
        guard.listener=socket(AF_UNIX,SOCK_STREAM,0);if(guard.listener<0)return 77;
        fcntl(guard.listener,F_SETFD,FD_CLOEXEC);
        unlink(guardSocketPath());struct sockaddr_un address={0};address.sun_family=AF_UNIX;strlcpy(address.sun_path,guardSocketPath(),sizeof(address.sun_path));
        if(bind(guard.listener,(struct sockaddr *)&address,sizeof(address))!=0||listen(guard.listener,8)!=0)return 77;
        chown(guardSocketPath(),protectedOwner(),userGroup);chmod(guardSocketPath(),0660);fcntl(guard.listener,F_SETFL,fcntl(guard.listener,F_GETFL)|O_NONBLOCK);
        dispatch_source_t listener=dispatch_source_create(DISPATCH_SOURCE_TYPE_READ,guard.listener,0,ObserverQueue);dispatch_source_set_event_handler(listener,^{[guard accept];});[guard.sources addObject:listener];
        for(NSNumber *sig in @[@(SIGTERM),@(SIGINT)]){signal(sig.intValue,SIG_IGN);dispatch_source_t s=dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL,sig.intValue,0,ObserverQueue);dispatch_source_set_event_handler(s,^{[guard stop];});[guard.sources addObject:s];}
        dispatch_source_t timer=dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER,0,0,ObserverQueue);dispatch_source_set_timer(timer,DISPATCH_TIME_NOW,10*NSEC_PER_SEC,100*NSEC_PER_MSEC);dispatch_source_set_event_handler(timer,^{@autoreleasepool{[guard tick];}});[guard.sources addObject:timer];
        dispatch_source_t maintenance=dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER,0,0,ObserverQueue);dispatch_source_set_timer(maintenance,dispatch_time(DISPATCH_TIME_NOW,60*NSEC_PER_SEC),60*NSEC_PER_SEC,100*NSEC_PER_MSEC);dispatch_source_set_event_handler(maintenance,^{@autoreleasepool{[guard.store maintain];}});[guard.sources addObject:maintenance];
        [guard.store setSensor:@"guard_integrity" status:@"active" detail:@"Root-owned writer, authenticated executable peers, SHA-256 event chain and ECDSA-P256 checkpoints"];
        [guard.store setSensor:@"guard_network_isolation" status:@"active" detail:@"IPv4 and IPv6 TCP/UDP connect and bind denied"];
        [guard.store record:@"guard_started" actor:AOProcess(getpid()) source:@"protected_writer" detail:@{@"target_uid":@(user),@"key_fingerprint":integrity.fingerprint} priority:2];
        [guard.store flush];[guard.store writeStatus];
        // No source can mutate the store until its initialization and first
        // checkpoint finish. From here on every mutation uses ObserverQueue.
        for(dispatch_source_t source in guard.sources)dispatch_resume(source);
        CFRunLoopRun();
    } @catch(NSException *error){fprintf(stderr,"Protected writer failed: %s\n",(error.reason ?: error.name).UTF8String);return 77;}
    return 0;
}
