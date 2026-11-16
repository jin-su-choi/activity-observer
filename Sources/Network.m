#import "Observer.h"
#import <dlfcn.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <libproc.h>
#import <fcntl.h>

// NetworkStatistics is also the OS source used by nettop. It is private API:
// symbol and callback availability are checked and failures are surfaced.
static void *framework, *manager;
static dispatch_queue_t networkQueue;
static void (^emitNetwork)(NSString *,NSDictionary *,NSDictionary *);
static void (*setDescription)(void *,void (^)(NSDictionary *));
static void (*setCounts)(void *,void (^)(NSDictionary *));
static void (*setRemoved)(void *,void (^)(void));
static void (*queryDescription)(void *);
static void (*queryAll)(void *,void (^)(void));
static void (*destroyManager)(void *);
static NSMutableDictionary *sources;

BOOL AOInternetSocketsBlocked(void) {
    // A local connect and an ephemeral bind exercise both sides of the policy
    // without using a destination outside this Mac.
    struct sockaddr_in loopback4={.sin_len=sizeof(loopback4),.sin_family=AF_INET,.sin_port=htons(9),.sin_addr={htonl(INADDR_LOOPBACK)}};
    struct sockaddr_in6 loopback6={.sin6_len=sizeof(loopback6),.sin6_family=AF_INET6,.sin6_port=htons(9),.sin6_addr=IN6ADDR_LOOPBACK_INIT};
    struct sockaddr *addresses[]={(struct sockaddr *)&loopback4,(struct sockaddr *)&loopback6};
    for(size_t i=0;i<sizeof(addresses)/sizeof(addresses[0]);i++) {
        struct sockaddr *address=addresses[i];
        const int types[]={SOCK_STREAM,SOCK_DGRAM};
        for(size_t j=0;j<sizeof(types)/sizeof(types[0]);j++) {
            int fd=socket(address->sa_family,types[j],0);
            if(fd<0) {
                if(errno==EACCES||errno==EPERM||errno==EAFNOSUPPORT)continue;
                return NO;
            }
            if(fcntl(fd,F_SETFL,O_NONBLOCK)!=0){close(fd);return NO;}
            int connected=connect(fd,address,address->sa_len);
            BOOL connectDenied=connected<0&&(errno==EACCES||errno==EPERM);
            close(fd);
            if(!connectDenied)return NO;

            fd=socket(address->sa_family,types[j],0);
            if(fd<0)return NO;
            struct sockaddr_storage local={0};
            memcpy(&local,address,address->sa_len);
            if(address->sa_family==AF_INET)((struct sockaddr_in *)&local)->sin_port=0;
            else ((struct sockaddr_in6 *)&local)->sin6_port=0;
            int bound=bind(fd,(struct sockaddr *)&local,address->sa_len);
            BOOL bindDenied=bound<0&&(errno==EACCES||errno==EPERM);
            close(fd);
            if(!bindDenied)return NO;
        }
    }
    return YES;
}

static id value(NSDictionary *d,NSArray *keys) { for(NSString *k in keys) if(d[k]) return d[k]; return nil; }
static NSDictionary *parentEvidence(NSDictionary *actor) {
    pid_t parent=[actor[@"ppid"] intValue];
    if(parent<=0)return nil;
    NSMutableDictionary *evidence=[@{@"pid":@(parent)} mutableCopy];
    struct proc_bsdinfo before={0},after={0};
    char path[PROC_PIDPATHINFO_MAXSIZE]={0};
    if(proc_pidinfo(parent,PROC_PIDTBSDINFO,0,&before,sizeof(before))==sizeof(before) &&
       before.pbi_start_tvsec+before.pbi_start_tvusec/1000000.0<=[actor[@"process_start"] doubleValue] &&
       proc_pidpath(parent,path,sizeof(path))>0 &&
       proc_pidinfo(parent,PROC_PIDTBSDINFO,0,&after,sizeof(after))==sizeof(after) &&
       before.pbi_start_tvsec==after.pbi_start_tvsec&&before.pbi_start_tvusec==after.pbi_start_tvusec) {
        evidence[@"path"]=@(path);
    }
    return evidence;
}
// The chain of parent executables, nearest first, and the process macOS holds
// responsible for the connecting one. A shell command leads back to its
// terminal or agent this way. Each step must have started before its child,
// which rejects a PID that was reused after the parent exited.
static pid_t (*responsiblePid)(pid_t);
static NSDictionary *lineage(NSDictionary *actor) {
    NSMutableDictionary *evidence=[NSMutableDictionary new];
    NSMutableArray *ancestors=[NSMutableArray new];
    pid_t parent=[actor[@"ppid"] intValue];double childStart=[actor[@"process_start"] doubleValue];
    for(int depth=0;depth<6&&parent>1;depth++) {
        struct proc_bsdinfo before={0},after={0};char path[PROC_PIDPATHINFO_MAXSIZE]={0};
        if(proc_pidinfo(parent,PROC_PIDTBSDINFO,0,&before,sizeof(before))!=sizeof(before))break;
        double started=before.pbi_start_tvsec+before.pbi_start_tvusec/1000000.0;
        if(childStart<=0||started>childStart||proc_pidpath(parent,path,sizeof(path))<=0||
           proc_pidinfo(parent,PROC_PIDTBSDINFO,0,&after,sizeof(after))!=sizeof(after)||
           before.pbi_start_tvsec!=after.pbi_start_tvsec||before.pbi_start_tvusec!=after.pbi_start_tvusec)break;
        [ancestors addObject:@(path)];
        childStart=started;parent=(pid_t)before.pbi_ppid;
    }
    if(ancestors.count)evidence[@"ancestors"]=ancestors;
    static dispatch_once_t once;
    dispatch_once(&once,^{responsiblePid=dlsym(RTLD_DEFAULT,"responsibility_get_pid_responsible_for_pid");});
    pid_t self=[actor[@"pid"] intValue],origin=responsiblePid&&self>0?responsiblePid(self):-1;
    if(origin>1&&origin!=self) {
        NSDictionary *process=AOProcess(origin);
        double started=[process[@"process_start"] doubleValue],own=[actor[@"process_start"] doubleValue];
        if([process[@"path"] length]&&started>0&&own>0&&started<=own)
            evidence[@"origin"]=@{@"pid":@(origin),@"path":process[@"path"],@"app":process[@"app"] ?: @""};
    }
    return evidence;
}
// The local port is chosen anew for every connection and is not recorded.
static NSString *addressOnly(NSString *endpoint) {
    NSRange colon=[endpoint rangeOfString:@":" options:NSBackwardsSearch];
    return colon.location==NSNotFound?endpoint:[endpoint substringToIndex:colon.location];
}
static BOOL matchesEarlierProcess(NSDictionary *candidate,NSDictionary *previous,NSString *name,NSTimeInterval observedAt) {
    NSNumber *started=candidate[@"process_start"],*previousStart=previous[@"process_start"];
    // Reject a PID that could have been assigned after the flow was observed.
    return started.doubleValue>0&&started.doubleValue<=observedAt&&
        (!previousStart||[previousStart isEqual:started])&&
        [[candidate[@"path"] lastPathComponent] isEqual:name];
}
static NSString *endpoint(id object) {
    if([object isKindOfClass:NSString.class]) return object;
    if(![object isKindOfClass:NSData.class] || [object length]<sizeof(struct sockaddr)) return @"";
    const struct sockaddr *sa=[object bytes]; char address[INET6_ADDRSTRLEN]={0}; int port=0;
    if(sa->sa_family==AF_INET && [object length]>=sizeof(struct sockaddr_in)) { const struct sockaddr_in *s=(const void *)sa; inet_ntop(AF_INET,&s->sin_addr,address,sizeof(address)); port=ntohs(s->sin_port); }
    else if(sa->sa_family==AF_INET6 && [object length]>=sizeof(struct sockaddr_in6)) { const struct sockaddr_in6 *s=(const void *)sa; inet_ntop(AF_INET6,&s->sin6_addr,address,sizeof(address)); port=ntohs(s->sin6_port); }
    return address[0] ? [NSString stringWithFormat:@"%s:%d",address,port] : @"";
}
BOOL AONetworkStart(void (^handler)(NSString *,NSDictionary *,NSDictionary *)) {
    framework=dlopen("/System/Library/PrivateFrameworks/NetworkStatistics.framework/NetworkStatistics",RTLD_NOW|RTLD_LOCAL);
    if(!framework) return NO;
    void *(*create)(CFAllocatorRef,dispatch_queue_t,void (^)(void *,void *))=dlsym(framework,"NStatManagerCreate");
    void (*tcp)(void *)=dlsym(framework,"NStatManagerAddAllTCP");
    void (*udp)(void *)=dlsym(framework,"NStatManagerAddAllUDP");
    setDescription=dlsym(framework,"NStatSourceSetDescriptionBlock"); setCounts=dlsym(framework,"NStatSourceSetCountsBlock");
    setRemoved=dlsym(framework,"NStatSourceSetRemovedBlock"); queryDescription=dlsym(framework,"NStatSourceQueryDescription");
    queryAll=dlsym(framework,"NStatManagerQueryAllSources"); destroyManager=dlsym(framework,"NStatManagerDestroy");
    if(!create||!tcp||!udp||!setDescription||!setCounts||!setRemoved||!queryAll) return NO;
    sources=[NSMutableDictionary new]; emitNetwork=[handler copy];
    networkQueue=dispatch_queue_create("local.activity-observer.network",dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL,QOS_CLASS_UTILITY,0));
    manager=create(kCFAllocatorDefault,networkQueue,^(void *source,void *unused){
        (void)unused;
        NSString *key=[NSString stringWithFormat:@"%p",source];
        if(sources.count>=8192) { emitNetwork(@"network_capacity",@{},@{@"reason":@"source limit reached"}); return; }
        NSMutableDictionary *state=[NSMutableDictionary new]; sources[key]=state;
        setDescription(source,^(NSDictionary *description){
            @autoreleasepool {
                pid_t pid=[value(description,@[@"processID",@"PID",@"Pid",@"pid",@"ProcessID"]) intValue];
                NSString *name=[value(description,@[@"ProcessName",@"Process",@"processName"]) description];
                NSDictionary *previousActor=state[@"actor"];
                BOOL samePID=previousActor&&[previousActor[@"pid"] intValue]==pid;
                NSMutableDictionary *actor;
                BOOL resolved=NO;
                if(!samePID) {
                    state[@"first_description_at"]=@(NSDate.date.timeIntervalSince1970);
                    [state removeObjectForKey:@"retried_actor"];
                    actor=[AOProcess(pid) mutableCopy];
                } else {
                    actor=[previousActor mutableCopy];
                    if(pid>0&&name.length&&![actor[@"path"] length]&&!state[@"retried_actor"]) {
                        state[@"retried_actor"]=@YES;
                        NSDictionary *candidate=AOProcess(pid);
                        if(matchesEarlierProcess(candidate,actor,name,[state[@"first_description_at"] doubleValue])) {
                            actor=[candidate mutableCopy];
                            resolved=YES;
                        }
                    }
                }
                NSString *remote=endpoint(value(description,@[@"Remote",@"RemoteAddress",@"remoteAddress"]));
                NSString *local=addressOnly(endpoint(value(description,@[@"Local",@"LocalAddress",@"localAddress"])));
                NSMutableDictionary *details=[@{@"remote":remote,@"local":local} mutableCopy];
                if(name.length) { details[@"process_name"]=name; if(![actor[@"path"] length]) actor[@"app"]=name; }
                id provider=value(description,@[@"provider",@"Provider",@"ProviderID"]); if(provider) details[@"provider"]=[provider description];
                details[@"protocol"]=description[@"TCPState"]?@"tcp":@"udp";
                if(pid<=0) {
                    details[@"schema_keys"]=[[description.allKeys sortedArrayUsingSelector:@selector(compare:)] componentsJoinedByString:@","];
                    NSMutableDictionary *identity=[NSMutableDictionary new];
                    for(NSString *k in description) if([[k lowercaseString] containsString:@"pid"]||[[k lowercaseString] containsString:@"process"]) identity[k]=[description[k] description];
                    details[@"identity_fields"]=identity;
                }
                BOOL connected=remote.length && ![remote isEqual:@"0.0.0.0:0"] && ![remote isEqual:@":::0"];
                NSDictionary *previous=state[@"detail"];
                state[@"actor"]=actor; state[@"detail"]=details;
                if(connected && ![state[@"announced"] boolValue]) {
                    state[@"announced"]=@YES;
                    NSMutableDictionary *open=[details mutableCopy];
                    NSDictionary *parent=parentEvidence(actor);
                    if(parent)open[@"parent"]=parent;
                    [open addEntriesFromDictionary:lineage(actor)];
                    emitNetwork(@"network_open",actor,open);
                } else if(connected) {
                    if(resolved) {
                        NSMutableDictionary *resolution=[details mutableCopy];
                        NSDictionary *parent=parentEvidence(actor);
                        if(parent)resolution[@"parent"]=parent;
                        [resolution addEntriesFromDictionary:lineage(actor)];
                        emitNetwork(@"network_actor_resolved",actor,resolution);
                    }
                    if(![previous[@"remote"] isEqual:remote])emitNetwork(@"network_peer_changed",actor,details);
                }
            }
        });
        setCounts(source,^(NSDictionary *counts){
            @autoreleasepool {
                uint64_t rx=[value(counts,@[@"RxBytes",@"RXBytes",@"rxBytes"]) unsignedLongLongValue];
                uint64_t tx=[value(counts,@[@"TxBytes",@"TXBytes",@"txBytes"]) unsignedLongLongValue];
                if([state[@"announced"] boolValue] && state[@"rx"]) {
                    uint64_t oldrx=[state[@"rx"] unsignedLongLongValue], oldtx=[state[@"tx"] unsignedLongLongValue];
                    uint64_t dr=rx>=oldrx?rx-oldrx:0,dt=tx>=oldtx?tx-oldtx:0;
                    if(dr||dt) { NSMutableDictionary *d=[state[@"detail"] mutableCopy]; d[@"rx_delta"]=@(dr); d[@"tx_delta"]=@(dt); emitNetwork(@"network_bytes",state[@"actor"],d); }
                }
                state[@"rx"]=@(rx); state[@"tx"]=@(tx);
            }
        });
        setRemoved(source,^{
            if([state[@"announced"] boolValue]) emitNetwork(@"network_close",state[@"actor"],state[@"detail"] ?: @{});
            [sources removeObjectForKey:key];
        });
        if(queryDescription) queryDescription(source);
    });
    if(!manager) return NO;
    tcp(manager); udp(manager); AONetworkQuery(); return YES;
}
void AONetworkQuery(void) { if(manager&&queryAll) dispatch_async(networkQueue,^{ queryAll(manager,^{}); }); }
void AONetworkStop(void) { if(manager&&destroyManager) { dispatch_sync(networkQueue,^{ destroyManager(manager); }); manager=NULL; } }
