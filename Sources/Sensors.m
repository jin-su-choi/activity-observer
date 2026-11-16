#import "Observer.h"
#import <AppKit/AppKit.h>
#import <CoreGraphics/CoreGraphics.h>
#import <CoreAudio/CoreAudio.h>
#import <CoreServices/CoreServices.h>
#import <IOKit/IOKitLib.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#import <signal.h>
#import <fcntl.h>
#import <sys/stat.h>

static NSArray *audioIDs(AudioObjectID object,AudioObjectPropertySelector selector,AudioObjectPropertyScope scope) {
    AudioObjectPropertyAddress a={selector,scope,kAudioObjectPropertyElementMain}; UInt32 size=0;
    if(AudioObjectGetPropertyDataSize(object,&a,0,NULL,&size)!=noErr || size>65536) return @[];
    NSMutableData *data=[NSMutableData dataWithLength:size];
    if(AudioObjectGetPropertyData(object,&a,0,NULL,&size,data.mutableBytes)!=noErr) return @[];
    NSMutableArray *result=[NSMutableArray new]; AudioObjectID *ids=data.mutableBytes;
    for(NSUInteger i=0;i<size/sizeof(AudioObjectID);i++) [result addObject:@(ids[i])]; return result;
}
static uint32_t audioNumber(AudioObjectID object,AudioObjectPropertySelector selector) {
    AudioObjectPropertyAddress a={selector,kAudioObjectPropertyScopeGlobal,kAudioObjectPropertyElementMain}; UInt32 value=0,size=sizeof(value);
    AudioObjectGetPropertyData(object,&a,0,NULL,&size,&value); return value;
}
static NSString *audioString(AudioObjectID object,AudioObjectPropertySelector selector) {
    AudioObjectPropertyAddress a={selector,kAudioObjectPropertyScopeGlobal,kAudioObjectPropertyElementMain}; CFStringRef s=NULL; UInt32 size=sizeof(s);
    if(AudioObjectGetPropertyData(object,&a,0,NULL,&size,&s)!=noErr || !s) return @""; return CFBridgingRelease(s);
}
// Repeated connections from one program to one destination are merged. The
// first is recorded at once and the rest of the window as a single summary.
static const NSTimeInterval AOConnectionWindow=300;
// A permission decision is recorded again after this long, so a standing
// grant stays visible without a row for every check.
static const NSTimeInterval AOPermissionRepeat=6*3600;

// Files that grant access or run code without being programs themselves: SSH
// access, shell startup, credential routing and the settings of coding agents.
static NSArray<NSArray<NSString *> *> *sensitiveFiles(void) {
    static NSArray *files;static dispatch_once_t once;
    dispatch_once(&once,^{
        NSString *home=NSHomeDirectory();NSMutableArray *list=[NSMutableArray new];
        void (^add)(NSString *,NSString *,NSArray *)=^(NSString *category,NSString *base,NSArray *names){
            for(NSString *name in names)[list addObject:@[category,[base stringByAppendingPathComponent:name]]];
        };
        add(@"ssh",[home stringByAppendingPathComponent:@".ssh"],@[@"authorized_keys",@"config",@"rc",@"environment"]);
        add(@"ssh",@"/etc/ssh",@[@"sshd_config"]);
        add(@"shell",home,@[@".zshenv",@".zprofile",@".zshrc",@".zlogin",@".zlogout",@".bash_profile",@".bashrc",@".bash_login",@".profile",@".config/fish/config.fish"]);
        add(@"shell",@"/etc",@[@"zshenv",@"zprofile",@"zshrc",@"profile",@"bashrc"]);
        add(@"system",@"/etc",@[@"hosts",@"sudoers",@"pam.d/sudo"]);
        add(@"credentials",home,@[@".gitconfig",@".config/git/config",@".npmrc",@".netrc"]);
        add(@"agent",home,@[@".claude/settings.json",@".claude/settings.local.json",@".claude.json",@"Library/Application Support/Claude/claude_desktop_config.json",@".codex/config.toml",@".codex/hooks.json",@".cursor/mcp.json",@".gemini/settings.json",@"Library/Application Support/Code/User/mcp.json"]);
        files=list;
    });
    return files;
}
// Agent state files change with every session. Only the parts that start
// programs or connect tools are compared: MCP server definitions and hooks.
static void collectSettings(id node,NSString *location,unsigned depth,NSMutableArray *found) {
    if(depth>4||![node isKindOfClass:NSDictionary.class])return;
    for(NSString *key in [[node allKeys] sortedArrayUsingSelector:@selector(compare:)]) {
        NSString *at=[location stringByAppendingFormat:@"/%@",key];
        if([key isEqual:@"mcpServers"]||[key isEqual:@"hooks"])[found addObject:@{@"at":at,@"value":node[key]}];
        else collectSettings(node[key],at,depth+1,found);
    }
}
static NSString *tomlSettings(NSString *text) {
    NSMutableString *kept=[NSMutableString new];BOOL keep=NO,table=NO;
    for(NSString *raw in [text componentsSeparatedByString:@"\n"]) {
        NSString *line=[raw stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
        if([line hasPrefix:@"["]) {
            table=YES;
            NSString *name=[line stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"[] "]];
            BOOL toolChoice=[name rangeOfString:@"^mcp_servers\\.[^.]+\\.tools(\\.|$)" options:NSRegularExpressionSearch].location!=NSNotFound;
            keep=([name hasPrefix:@"mcp_servers"]&&!toolChoice)||[name hasPrefix:@"shell_environment_policy"]||[name hasPrefix:@"marketplaces"]||
                [name hasPrefix:@"plugins"]||([name hasPrefix:@"hooks"]&&![name hasPrefix:@"hooks.state"]);
        }
        if(keep||(!table&&[line hasPrefix:@"notify"]))[kept appendFormat:@"%@\n",raw];
    }
    return kept;
}
static NSDictionary *sensitiveState(NSString *path) {
    struct stat link,st;
    if(lstat(path.fileSystemRepresentation,&link)!=0)return @{@"exists":@NO,@"sha256":@"absent",@"signature":@"absent"};
    NSMutableDictionary *state=[@{@"exists":@YES} mutableCopy];
    if(S_ISLNK(link.st_mode))state[@"link_target"]=[NSFileManager.defaultManager destinationOfSymbolicLinkAtPath:path error:nil] ?: @"";
    if(stat(path.fileSystemRepresentation,&st)!=0)st=link;
    state[@"size"]=@(st.st_size);state[@"mode"]=[NSString stringWithFormat:@"%o",st.st_mode&07777];state[@"owner"]=@(st.st_uid);
    state[@"modified"]=@(st.st_mtimespec.tv_sec);
    state[@"signature"]=[NSString stringWithFormat:@"%lld:%ld.%ld:%llu:%o:%u:%@",(long long)st.st_size,(long)st.st_mtimespec.tv_sec,(long)st.st_mtimespec.tv_nsec,(unsigned long long)st.st_ino,st.st_mode,st.st_uid,state[@"link_target"] ?: @""];
    return state;
}
// The digest covers the whole file, or only its settings for agent state files.
static void sensitiveDigest(NSString *path,NSMutableDictionary *state) {
    NSString *metadata=[@"metadata:" stringByAppendingString:state[@"signature"]];
    NSData *bytes=[state[@"size"] unsignedLongLongValue]<=4*1024*1024?[NSData dataWithContentsOfFile:path options:0 error:nil]:nil;
    if(!bytes){state[@"sha256"]=metadata;state[@"scope"]=@"metadata";return;}
    state[@"scope"]=@"content";
    if([path.lastPathComponent isEqual:@".claude.json"]) {
        id json=[NSJSONSerialization JSONObjectWithData:bytes options:0 error:nil];NSMutableArray *found=[NSMutableArray new];
        if([json isKindOfClass:NSDictionary.class]){collectSettings(json,@"",0,found);bytes=[AOJSON(found) dataUsingEncoding:NSUTF8StringEncoding];state[@"scope"]=@"mcp_servers_and_hooks";}
    } else if([path hasSuffix:@".codex/config.toml"]) {
        NSString *text=[[NSString alloc] initWithData:bytes encoding:NSUTF8StringEncoding];
        if(text){bytes=[tomlSettings(text) dataUsingEncoding:NSUTF8StringEncoding];state[@"scope"]=@"servers_plugins_hooks_environment";}
    }
    state[@"sha256"]=AOHash(bytes);
}
static NSString *logField(NSString *text,NSString *name,NSString *terminators) {
    NSRange start=[text rangeOfString:name];if(start.location==NSNotFound)return nil;
    NSUInteger from=NSMaxRange(start);
    NSRange end=[text rangeOfCharacterFromSet:[NSCharacterSet characterSetWithCharactersInString:terminators] options:0 range:NSMakeRange(from,text.length-from)];
    NSString *value=[text substringWithRange:NSMakeRange(from,(end.location==NSNotFound?text.length:end.location)-from)];
    value=[value stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
    return value.length>1024?[value substringToIndex:1024]:value;
}
static NSString *appRoot(NSString *path) {
    NSRange boundary=[path rangeOfString:@".app/"];
    return boundary.location==NSNotFound?path:[path substringToIndex:boundary.location+4];
}

// Both queues belong to fileInputQueue. File I/O and signing never run there.
// Account for string storage and per-entry overhead, with a separate count cap.
// Repeated bundle changes share one entry and a bounded set of example paths.
@interface AOFileQueue : NSObject
@property NSMutableDictionary *entries;
@property NSMutableOrderedSet *order;
@property NSMutableOrderedSet *overflowPaths;
@property NSUInteger bytes;
@property NSUInteger maxBytes;
@property NSUInteger dropped;
- (BOOL)add:(NSString *)path changed:(NSArray *)changed flags:(unsigned)flags source:(NSString *)source at:(NSTimeInterval)at;
- (NSArray *)take:(NSUInteger)limit;
- (NSDictionary *)takeOverflow;
@end
@implementation AOFileQueue
- (instancetype)init {
    if((self=[super init])){_entries=[NSMutableDictionary new];_order=[NSMutableOrderedSet new];_overflowPaths=[NSMutableOrderedSet new];_maxBytes=16*1024*1024;}
    return self;
}
- (BOOL)add:(NSString *)path changed:(NSArray *)changed flags:(unsigned)flags source:(NSString *)source at:(NSTimeInterval)at {
    NSMutableDictionary *entry=_entries[path];
    if(!entry){
        NSString *first=changed.firstObject;
        if([first isEqual:path])first=path;
        NSUInteger size=512+path.length*2+(first&&first!=path?64+first.length*2:0);
        if(_entries.count>=32768 || size>_maxBytes-MIN(_bytes,_maxBytes)){
            _dropped++;if(_overflowPaths.count<8)[_overflowPaths addObject:path];return NO;
        }
        NSMutableOrderedSet *samples=[NSMutableOrderedSet new];if(first)[samples addObject:first];
        entry=[@{@"path":path,@"changed":samples,@"flags":@0,@"source":source,@"received":@(at),@"bytes":@(size)} mutableCopy];
        _entries[path]=entry;[_order addObject:path];_bytes+=size;
    }
    entry[@"flags"]=@([entry[@"flags"] unsignedIntValue]|flags);
    // Keep FSEvents creation evidence when other discovery paths coalesce here.
    if([source isEqual:@"fsevents"])entry[@"source"]=source;
    NSMutableOrderedSet *samples=entry[@"changed"];
    for(NSString *item in changed){
        NSUInteger cost=64+item.length*2;
        if(samples.count>=24)break;
        if([samples containsObject:item]||cost>_maxBytes-MIN(_bytes,_maxBytes))continue;
        [samples addObject:item];_bytes+=cost;entry[@"bytes"]=@([entry[@"bytes"] unsignedIntegerValue]+cost);
    }
    return YES;
}
- (NSArray *)take:(NSUInteger)limit {
    NSIndexSet *indexes=[NSIndexSet indexSetWithIndexesInRange:NSMakeRange(0,MIN(limit,_order.count))];
    NSArray *keys=[_order objectsAtIndexes:indexes];NSMutableArray *batch=[NSMutableArray new];
    for(NSString *path in keys){NSMutableDictionary *entry=_entries[path];_bytes-=[entry[@"bytes"] unsignedIntegerValue];[batch addObject:entry];[_entries removeObjectForKey:path];}
    [_order removeObjectsAtIndexes:indexes];return batch;
}
- (NSDictionary *)takeOverflow {
    NSDictionary *result=@{@"dropped":@(_dropped),@"paths":[_overflowPaths.array copy]};
    _dropped=0;[_overflowPaths removeAllObjects];return result;
}
@end
static NSString *physicalPath(NSString *path) {
    NSMutableArray *suffix=[NSMutableArray new];NSString *prefix=path;char *resolved=NULL;
    while(!(resolved=realpath(prefix.fileSystemRepresentation,NULL))&&prefix.length>1){[suffix addObject:prefix.lastPathComponent];prefix=prefix.stringByDeletingLastPathComponent;}
    NSString *result=resolved?@(resolved):prefix;if(resolved)free(resolved);
    for(NSString *component in suffix.reverseObjectEnumerator)result=[result stringByAppendingPathComponent:component];return result;
}
static NSArray *fileWatchRoots(NSArray *candidates) {
    NSMutableSet *available=[NSMutableSet new];
    for(NSString *candidate in candidates){
        NSString *path=candidate;BOOL directory=NO;
        while(path.length>1&&(![NSFileManager.defaultManager fileExistsAtPath:path isDirectory:&directory]||!directory))path=path.stringByDeletingLastPathComponent;
        [available addObject:path];
    }
    NSArray *sorted=[available.allObjects sortedArrayUsingComparator:^NSComparisonResult(NSString *a,NSString *b){return a.length==b.length?[a compare:b]:a.length<b.length?NSOrderedAscending:NSOrderedDescending;}];
    NSMutableArray *roots=[NSMutableArray new];
    for(NSString *path in sorted){BOOL covered=NO;for(NSString *parent in roots)if([parent isEqual:@"/"]||[path hasPrefix:[parent stringByAppendingString:@"/"]]){covered=YES;break;}if(!covered)[roots addObject:path];}
    return roots;
}
static BOOL cachePath(NSString *path) {
    static NSSet *names;static dispatch_once_t once;
    dispatch_once(&once,^{names=[NSSet setWithArray:@[@"cache",@"caches",@"gpucache",@"code cache",@"indexeddb",@"local storage",@"blob_storage",@"logs",@".git",@"__pycache__"]];});
    for(NSString *part in path.pathComponents) if([names containsObject:part.lowercaseString]) return YES;
    return NO;
}
static BOOL programFile(NSString *path) {
    struct stat before;if(lstat(path.fileSystemRepresentation,&before)!=0||!S_ISREG(before.st_mode)||!(before.st_mode&0111))return NO;
    int fd=open(path.fileSystemRepresentation,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
    if(fd<0)return NO;struct stat st;unsigned char magic[4]={0};
    BOOL valid=fstat(fd,&st)==0&&S_ISREG(st.st_mode)&&(st.st_mode&0111)&&read(fd,magic,4)>=2;close(fd);
    if(!valid)return NO;
    uint32_t m=0;memcpy(&m,magic,4);
    return (magic[0]=='#'&&magic[1]=='!')||m==0xfeedface||m==0xfeedfacf||m==0xcefaedfe||m==0xcffaedfe||m==0xcafebabe||m==0xbebafeca||m==0xcafebabf||m==0xbfbafeca;
}
static NSString *versionFamily(NSString *path) {
    NSMutableArray *parts=[NSMutableArray new];
    for(NSString *part in path.pathComponents) {
        BOOL version=[part rangeOfString:@"^v?[0-9]+(\\.[0-9]+){1,3}([.-][A-Za-z0-9_-]+)?$" options:NSRegularExpressionSearch].location!=NSNotFound;
        BOOL hash=[part rangeOfString:@"^[a-fA-F0-9]{8,64}$" options:NSRegularExpressionSearch].location!=NSNotFound;
        [parts addObject:version?@"<version>":hash?@"<build>":part];
    }
    return [NSString pathWithComponents:parts];
}

@interface AOCollector ()
@property AOStore *store;
@property NSArray<NSString *> *roots;
@property NSArray<NSString *> *watchRoots;
@property NSArray<NSString *> *eventRoots;
@property NSTimeInterval lastRootCheck;
@property NSMutableArray *timers;
@property NSMutableDictionary *taps;
@property NSMutableDictionary *hidClients;
@property NSMutableDictionary *audioClients;
@property NSMutableDictionary *audioListeners;
@property NSMutableSet *captureAttributions;
@property NSMutableSet *observedExecutables;
@property NSTimeInterval observationStarted;
@property NSMutableDictionary *capturePIDs;
@property NSTask *logTask;
@property NSMutableData *logBuffer;
@property NSMutableData *errorBuffer;
@property BOOL stopping;
@property BOOL baseline;
@property NSTimeInterval lastNetwork;
@property NSTimeInterval lastLogRecord;
@property NSUInteger unknownLogs;
@property NSUInteger networkEvents;
@property FSEventStreamRef fsStream;
@property NSTimeInterval lastInventorySweep;
@property BOOL inventoryRecoveryPending;
@property NSMutableArray *workspaceObservers;
@property NSMutableDictionary *networkTraffic;
@property dispatch_queue_t fileInputQueue;
@property dispatch_queue_t fileClassifyQueue;
@property dispatch_queue_t fileWorkQueue;
@property dispatch_source_t fileTimer;
@property dispatch_source_t fileDrainSource;
@property dispatch_source_t fileProcessSource;
@property AOFileQueue *fileInbox;
@property AOFileQueue *fileReady;
@property NSMutableSet *knownFilePaths;
@property NSUInteger fileSignals;
@property unsigned fileSignalFlags;
@property NSTimeInterval fileSignalTime;
@property NSTimeInterval lastFileDelayReport;
@property NSTimeInterval nextFileDrain;
@property NSTimeInterval nextFileProcess;
@property BOOL fileDrainScheduled;
@property BOOL fileProcessScheduled;
@property NSMutableDictionary *inventoryRun;
@property NSDirectoryEnumerator *inventoryEnumerator;
@property NSArray *knownInventory;
@property NSUInteger knownInventoryCursor;
@property NSUInteger inventoryRootCursor;
@property NSUInteger inventoryRootEntries;
@property BOOL inventoryAppRoot;
@property NSMutableSet *inventoryChecked;
@property NSMutableDictionary *connectionWindows;
@property NSMutableDictionary *sensitiveSeen;
@property dispatch_source_t sensitiveTimer;
@property NSMutableDictionary *permissionRequests;
@property NSMutableDictionary *permissionSeen;

@end

static void fileEvents(ConstFSEventStreamRef stream,void *context,size_t count,void *paths,const FSEventStreamEventFlags flags[],const FSEventStreamEventId ids[]) {
    (void)stream;(void)ids;
    AOCollector *self=(__bridge AOCollector *)context;if(self.stopping)return;
    NSArray *array=(__bridge NSArray *)paths;NSTimeInterval now=NSDate.date.timeIntervalSince1970;
    // This queue only coalesces strings and flags. No filesystem, signing,
    // inventory lookup, or writer calls may block FSEvents delivery here.
    for(size_t i=0;i<count;i++) {@autoreleasepool{
        NSString *path=array[i];BOOL relevant=NO;
        for(NSString *root in self.eventRoots)if([path isEqual:root]||[path hasPrefix:[root stringByAppendingString:@"/"]]){relevant=YES;break;}
        if(flags[i]&(kFSEventStreamEventFlagUserDropped|kFSEventStreamEventFlagKernelDropped|kFSEventStreamEventFlagMustScanSubDirs)) {
            self.fileSignals++;self.fileSignalFlags|=flags[i];self.fileSignalTime=now;
        }
        if(!relevant)continue;
        if([path isEqual:self.store.directory]||[path hasPrefix:[self.store.directory stringByAppendingString:@"/"]])continue;
        NSString *group=appRoot(path);
        // Directory metadata alone cannot identify a new executable. Retain
        // creation/removal/rename signals, known paths and all app-bundle changes.
        unsigned structural=kFSEventStreamEventFlagItemCreated|kFSEventStreamEventFlagItemRemoved|kFSEventStreamEventFlagItemRenamed|kFSEventStreamEventFlagMustScanSubDirs|kFSEventStreamEventFlagRootChanged;
        if((flags[i]&kFSEventStreamEventFlagItemIsDir)&&!(flags[i]&structural)&&![group.pathExtension isEqual:@"app"]&&![self.knownFilePaths containsObject:group])continue;
        if(![self.fileInbox add:group changed:@[path] flags:flags[i] source:@"fsevents" at:now])self.fileSignalTime=now;
    }}
    dispatch_source_t signal=self.fileDrainSource;if(signal)dispatch_source_merge_data(signal,1);
}

@implementation AOCollector
- (instancetype)initWithStore:(AOStore *)store roots:(NSArray<NSString *> *)roots {
    if((self=[super init])) {
        _store=store; NSMutableArray *canonicalRoots=[NSMutableArray new];for(NSString *root in roots)[canonicalRoots addObject:root.stringByResolvingSymlinksInPath];_roots=canonicalRoots;NSMutableArray *eventRoots=[NSMutableArray new];for(NSString *root in roots)[eventRoots addObject:physicalPath(root)];_eventRoots=eventRoots; _timers=[NSMutableArray new]; _taps=[NSMutableDictionary new]; _hidClients=[NSMutableDictionary new];
        _audioClients=[NSMutableDictionary new]; _audioListeners=[NSMutableDictionary new]; _captureAttributions=[NSMutableSet new];
        _capturePIDs=[NSMutableDictionary new]; _logBuffer=[NSMutableData new]; _errorBuffer=[NSMutableData new];
        _observedExecutables=[NSMutableSet new];_observationStarted=NSDate.date.timeIntervalSince1970;
        _workspaceObservers=[NSMutableArray new];
        _networkTraffic=[NSMutableDictionary new];
        _connectionWindows=[NSMutableDictionary new];_sensitiveSeen=[NSMutableDictionary new];
        _permissionRequests=[NSMutableDictionary new];_permissionSeen=[NSMutableDictionary new];
        _fileInbox=[AOFileQueue new];_fileReady=[AOFileQueue new];
        _knownFilePaths=[NSMutableSet setWithArray:[[store query:@"SELECT path,detail FROM inventory" arguments:@[]] valueForKey:@"path"]];
        dispatch_queue_attr_t fileAttr=dispatch_queue_attr_make_with_autorelease_frequency(dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL,QOS_CLASS_UTILITY,0),DISPATCH_AUTORELEASE_FREQUENCY_WORK_ITEM);
        _fileInputQueue=dispatch_queue_create("local.activity-observer.files.input",fileAttr);
        _fileClassifyQueue=dispatch_queue_create("local.activity-observer.files.classify",fileAttr);
        _fileWorkQueue=dispatch_queue_create("local.activity-observer.files.work",fileAttr);
        _baseline=[store query:@"SELECT 1 FROM state WHERE key='baseline_complete'" arguments:@[]].count==0;
    } return self;
}
- (void)timer:(double)seconds action:(dispatch_block_t)action {
    dispatch_source_t t=dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER,0,0,ObserverQueue);
    dispatch_source_set_timer(t,dispatch_time(DISPATCH_TIME_NOW,(int64_t)(seconds*NSEC_PER_SEC)),(uint64_t)(seconds*NSEC_PER_SEC),100*NSEC_PER_MSEC);
    dispatch_source_set_event_handler(t,^{ @autoreleasepool { action(); } }); dispatch_resume(t); [_timers addObject:t];
}
- (void)start {
    [self startFileProcessing]; [self startLog]; [self startFiles]; [self scanTaps]; [self scanHID]; [self refreshAudio];
    __weak AOCollector *weak=self;
    NSNotificationCenter *workspace=NSWorkspace.sharedWorkspace.notificationCenter;
    for(NSNotificationName name in @[NSWorkspaceDidLaunchApplicationNotification,NSWorkspaceDidTerminateApplicationNotification]) {
        id observer=[workspace addObserverForName:name object:nil queue:nil usingBlock:^(NSNotification *notification){
            NSRunningApplication *app=notification.userInfo[NSWorkspaceApplicationKey];
            NSDictionary *actor=@{@"app":app.bundleIdentifier ?: app.localizedName ?: @"unknown",@"pid":@(app.processIdentifier),@"path":app.executableURL.path ?: @""};
            BOOL launch=[name isEqual:NSWorkspaceDidLaunchApplicationNotification];
            dispatch_async(ObserverQueue,^{
                AOCollector *s=weak; if(!s||s.stopping) return;
                [s.store record:launch?@"application_launched":@"application_terminated" actor:actor source:@"nsworkspace" detail:@{} priority:1];
                if(launch && app.bundleURL.path) {
                    NSString *path=app.bundleURL.path;
                    dispatch_async(s.fileWorkQueue,^{if(!s.stopping)[s fingerprint:path.stringByResolvingSymlinksInPath changed:@[] initial:NO flags:0 source:@"nsworkspace"];});
                }
            });
        }];
        [_workspaceObservers addObject:observer];
    }
    [_store setSensor:@"application_lifecycle" status:@"active" detail:@"NSWorkspace application launch/termination notifications, including apps outside watched install directories"];
    [_store setSensor:@"program_discovery" status:@"active" detail:@"User-local and Application Support code changes plus first-seen network executables; cache/data events filtered"];
    AudioObjectPropertyAddress a={kAudioHardwarePropertyProcessObjectList,kAudioObjectPropertyScopeGlobal,kAudioObjectPropertyElementMain};
    AudioObjectPropertyListenerBlock audioBlock=^(UInt32 n,const AudioObjectPropertyAddress *addresses){ (void)n;(void)addresses; [weak refreshAudio]; };
    OSStatus audioStatus=AudioObjectAddPropertyListenerBlock(kAudioObjectSystemObject,&a,ObserverQueue,audioBlock);
    _audioListeners[@"system"]=audioBlock;
    [_store setSensor:@"audio" status:audioStatus==noErr?@"active":@"degraded" detail:audioStatus==noErr?@"Core Audio process input-state notifications; no audio samples read":@"Could not subscribe to Core Audio notifications"];
    BOOL network=AONetworkStart(^(NSString *kind,NSDictionary *actor,NSDictionary *detail){
        dispatch_async(ObserverQueue,^{
            AOCollector *s=weak; if(!s||s.stopping) return;
            s.lastNetwork=NSDate.date.timeIntervalSince1970; s.networkEvents++;
            if([kind isEqual:@"network_open"]) [s observeProgram:actor];
            if([kind isEqual:@"network_bytes"]) [s accumulateTraffic:actor detail:detail];
            else if([kind isEqual:@"network_open"]||[kind isEqual:@"network_close"]) [s recordConnection:kind actor:actor detail:detail];
            else [s.store record:kind actor:actor source:@"networkstatistics" detail:detail priority:0];
        });
    });
    [_store setSensor:@"network" status:network?@"starting":@"unavailable" detail:network?@"Waiting for native TCP/UDP source callbacks":@"NetworkStatistics API unavailable; network coverage is absent"];
    dispatch_async(_fileWorkQueue,^{[self inventory];});
    _fileTimer=dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER,0,0,_fileWorkQueue);
    dispatch_source_set_timer(_fileTimer,dispatch_time(DISPATCH_TIME_NOW,NSEC_PER_SEC),NSEC_PER_SEC,100*NSEC_PER_MSEC);
    dispatch_source_set_event_handler(_fileTimer,^{@autoreleasepool{AOCollector *s=weak;if(!s||s.stopping)return;if(!s.inventoryRun&&(s.inventoryRecoveryPending||NSDate.date.timeIntervalSince1970-s.lastInventorySweep>21600))[s inventory];[s inventoryStep];if(NSDate.date.timeIntervalSince1970-s.lastRootCheck>=5){s.lastRootCheck=NSDate.date.timeIntervalSince1970;NSMutableArray *eventRoots=[NSMutableArray new];for(NSString *root in s.roots)[eventRoots addObject:physicalPath(root)];s.eventRoots=eventRoots;NSArray *roots=fileWatchRoots(s.roots);if(![roots isEqual:s.watchRoots])dispatch_async(ObserverQueue,^{if(!s.stopping)[s replaceFileStream:roots];});}}});
    dispatch_resume(_fileTimer);
    _sensitiveTimer=dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER,0,0,_fileWorkQueue);
    dispatch_source_set_timer(_sensitiveTimer,dispatch_time(DISPATCH_TIME_NOW,5*NSEC_PER_SEC),30*NSEC_PER_SEC,NSEC_PER_SEC);
    dispatch_source_set_event_handler(_sensitiveTimer,^{@autoreleasepool{AOCollector *s=weak;if(s&&!s.stopping)[s checkSensitiveFiles];}});
    dispatch_resume(_sensitiveTimer);
    [_store setSensor:@"sensitive_files" status:@"active" detail:@"SSH, shell startup, credential routing and agent settings files compared every 30 seconds; contents are hashed, not stored"];
    [self timer:1 action:^{ [weak scanTaps]; }];
    [self timer:5 action:^{ [weak scanHID]; AONetworkQuery(); }];
    [self timer:10 action:^{
        AOCollector *s=weak; if(!s) return;
        [s.store flush]; [s.store writeStatus];
        if(s.networkEvents) [s.store setSensor:@"network" status:@"active" detail:@"Native TCP/UDP source lifecycle callbacks; byte counters queried every 5 seconds"];
        if(![s.store isKindOfClass:AOAgentStore.class]&&!s.logTask.running&&!s.stopping) [s startLog];
    }];
    [self timer:60 action:^{
        AOCollector *s=weak; if(!s) return;
        [s flushTraffic]; [s flushConnections:NO]; [s.store maintain];
        if(s.networkEvents==0) [s.store setSensor:@"network" status:@"degraded" detail:@"No native connection callback received; do not interpret this as no network activity"];

    }];
    [_store setSensor:@"endpoint_security" status:@"not_enabled" detail:@"No privileged ES client installed. HID connections are reconciled from IORegistry; process execution is not a complete kernel audit."];
    [_store record:@"collector_started" actor:AOProcess(getpid()) source:@"collector" detail:@{@"version":@AO_VERSION,@"os":NSProcessInfo.processInfo.operatingSystemVersionString} priority:2];
    [_store flush]; [_store writeStatus];
}
- (void)observeProgram:(NSDictionary *)actor {
    NSString *path=actor[@"path"];if(![path isKindOfClass:NSString.class]||!path.isAbsolutePath)return;
    NSString *raw=appRoot(path);if([_observedExecutables containsObject:raw])return;
    if(_observedExecutables.count>=8192){[_store setSensor:@"program_discovery" status:@"degraded" detail:@"Observed executable cache limit reached"];return;}
    [_observedExecutables addObject:raw];
    dispatch_async(_fileClassifyQueue,^{
        if(self.stopping)return;
        [self queueProgram:raw.stringByResolvingSymlinksInPath changed:@[] flags:0 source:@"network_activity" at:NSDate.date.timeIntervalSince1970];
    });
}
- (void)startFileProcessing {
    __weak AOCollector *weak=self;
    _fileDrainSource=dispatch_source_create(DISPATCH_SOURCE_TYPE_DATA_ADD,0,0,_fileClassifyQueue);
    dispatch_source_set_event_handler(_fileDrainSource,^{@autoreleasepool{[weak drainFileEvents];}});dispatch_resume(_fileDrainSource);
    _fileProcessSource=dispatch_source_create(DISPATCH_SOURCE_TYPE_DATA_ADD,0,0,_fileWorkQueue);
    dispatch_source_set_event_handler(_fileProcessSource,^{@autoreleasepool{[weak processPaths];}});dispatch_resume(_fileProcessSource);
}
- (void)queueProgram:(NSString *)path changed:(NSArray *)changed flags:(unsigned)flags source:(NSString *)source at:(NSTimeInterval)at {
    dispatch_sync(_fileInputQueue,^{[self.fileReady add:path changed:changed flags:flags source:source at:at];});
    dispatch_source_t signal=self.fileProcessSource;if(signal)dispatch_source_merge_data(signal,1);
}

- (NSArray *)fileQuery:(NSString *)sql arguments:(NSArray *)arguments {
    __block NSArray *rows=@[];dispatch_sync(ObserverQueue,^{if(!self.stopping)rows=[self.store query:sql arguments:arguments];});return rows;
}
- (BOOL)fileExecute:(NSString *)sql arguments:(NSArray *)arguments {
    __block BOOL ok=NO;dispatch_sync(ObserverQueue,^{if(!self.stopping)ok=[self.store execute:sql arguments:arguments];});return ok;
}
- (void)fileRecord:(NSString *)kind actor:(NSDictionary *)actor source:(NSString *)source detail:(NSDictionary *)detail priority:(NSInteger)priority {
    dispatch_sync(ObserverQueue,^{if(!self.stopping)[self.store record:kind actor:actor source:source detail:detail priority:priority];});
}
- (void)reportFileOverflow:(NSDictionary *)overflow queue:(NSString *)queue queued:(NSUInteger)queued flags:(unsigned)flags signals:(NSUInteger)signals observedAt:(NSTimeInterval)at {
    NSUInteger dropped=[overflow[@"dropped"] unsignedIntegerValue];if(!dropped&&!signals)return;
    [self fileRecord:@"collection_gap" actor:@{@"app":@"activity-observer",@"pid":@(getpid())} source:@"fsevents" detail:@{
        @"reason":dropped?@"file queue exceeded its memory or entry limit":@"filesystem stream requires rescan",
        @"queue":queue,@"flags":@(flags),@"signals":@(signals),@"queue_dropped":@(dropped),@"ingress_dropped":@([queue isEqual:@"classification"]?dropped:0),
        @"queued_paths":@(queued),@"overflow_paths":overflow[@"paths"],@"observed_at":@(at)} priority:3];
    if(dropped)dispatch_sync(ObserverQueue,^{if(!self.stopping)self.store.dropped+=dropped;});
    dispatch_async(_fileWorkQueue,^{if(!self.stopping)self.inventoryRecoveryPending=YES;});
}
- (void)drainFileEvents {
    if(self.stopping)return;
    NSTimeInterval clock=NSProcessInfo.processInfo.systemUptime;
    if(clock<_nextFileDrain){
        if(!_fileDrainScheduled){_fileDrainScheduled=YES;dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)((_nextFileDrain-clock)*NSEC_PER_SEC)),_fileClassifyQueue,^{self.fileDrainScheduled=NO;@autoreleasepool{[self drainFileEvents];}});}return;
    }
    __block NSArray *batch;__block NSSet *known;__block NSDictionary *overflow;
    __block NSUInteger signals,queued;__block unsigned flags;__block NSTimeInterval signalTime;
    dispatch_sync(_fileInputQueue,^{
        queued=self.fileInbox.entries.count;batch=[self.fileInbox take:64];known=[self.knownFilePaths copy];overflow=[self.fileInbox takeOverflow];
        signals=self.fileSignals;flags=self.fileSignalFlags;signalTime=self.fileSignalTime;self.fileSignals=0;self.fileSignalFlags=0;
    });
    [self reportFileOverflow:overflow queue:@"classification" queued:queued flags:flags signals:signals observedAt:signalTime];
    NSTimeInterval started=NSDate.date.timeIntervalSince1970,oldest=started;
    for(NSDictionary *entry in batch){@autoreleasepool{
        if(self.stopping)return;NSString *container=entry[@"path"];oldest=MIN(oldest,[entry[@"received"] doubleValue]);
        NSString *root=container.stringByResolvingSymlinksInPath;BOOL bundle=[container.pathExtension isEqual:@"app"];
        BOOL relevant=bundle||[known containsObject:root]||[container containsString:@"LaunchAgents/"]||[container containsString:@"LaunchDaemons/"]||[container containsString:@"PrivilegedHelperTools/"];
        // Unknown executable files remain observable even in cache directories.
        if(!relevant)relevant=programFile(root);
        if(relevant)[self queueProgram:root changed:[entry[@"changed"] array] flags:[entry[@"flags"] unsignedIntValue] source:entry[@"source"] at:[entry[@"received"] doubleValue]];
    }}
    NSTimeInterval elapsed=NSProcessInfo.processInfo.systemUptime-clock;
    if((started-oldest>5||elapsed>2)&&started-_lastFileDelayReport>60){_lastFileDelayReport=started;[self fileRecord:@"filesystem_work_delayed" actor:@{@"app":@"activity-observer"} source:@"fsevents" detail:@{@"stage":@"classification",@"oldest_wait_seconds":@(started-oldest),@"batch_seconds":@(elapsed),@"queued_paths":@(queued)} priority:2];}
    _nextFileDrain=NSProcessInfo.processInfo.systemUptime+MIN(0.05,MAX(0.002,elapsed*3));
    __block BOOL more;dispatch_sync(_fileInputQueue,^{more=self.fileInbox.entries.count>0||self.fileSignals>0||self.fileInbox.dropped>0;});
    dispatch_source_t signal=_fileDrainSource;if(more&&signal)dispatch_source_merge_data(signal,1);
}
- (void)accumulateTraffic:(NSDictionary *)actor detail:(NSDictionary *)detail {
    NSTimeInterval now=NSDate.date.timeIntervalSince1970;
    NSString *path=[actor[@"path"] isKindOfClass:NSString.class]?actor[@"path"]:@"";
    NSString *key=AOJSON(@[AODay(now),actor[@"app"] ?: @"unknown",path,detail[@"protocol"] ?: @"",detail[@"remote"] ?: @""]);
    BOOL overflow=_networkTraffic.count>=4096 && !_networkTraffic[key];
    if(overflow) key=@"overflow";
    NSMutableDictionary *entry=_networkTraffic[key];
    if(!entry) {
        NSMutableDictionary *application=overflow?[@{@"app":@"unattributed-traffic",@"path":@""} mutableCopy]:[actor mutableCopy]; application[@"pid"]=@0;
        entry=[@{@"actor":application,@"remote":overflow?@"aggregated-overflow":detail[@"remote"] ?: @"",@"protocol":detail[@"protocol"] ?: @"",@"first":@(now),@"last":@(now),@"rx":@0,@"tx":@0,@"samples":@0,@"overflow":@(overflow)} mutableCopy];
        _networkTraffic[key]=entry;
        if(overflow)[_store record:@"collection_gap" actor:@{@"app":@"activity-observer"} source:@"networkstatistics" detail:@{@"reason":@"Traffic attribution capacity exceeded; excess bytes remain unattributed"} priority:3];
    }
    entry[@"rx"]=@([entry[@"rx"] unsignedLongLongValue]+[detail[@"rx_delta"] unsignedLongLongValue]);
    entry[@"tx"]=@([entry[@"tx"] unsignedLongLongValue]+[detail[@"tx_delta"] unsignedLongLongValue]);
    entry[@"samples"]=@([entry[@"samples"] unsignedLongLongValue]+1); entry[@"last"]=@(now);
}
// Merging uses the program, the destination and the launching chain. Process
// IDs are kept as examples so that short-lived tools still collapse.
- (void)recordConnection:(NSString *)kind actor:(NSDictionary *)actor detail:(NSDictionary *)detail {
    NSTimeInterval now=NSDate.date.timeIntervalSince1970;
    NSInteger priority=[kind isEqual:@"network_open"]?1:0;
    NSString *path=[actor[@"path"] isKindOfClass:NSString.class]?actor[@"path"]:@"";
    NSString *parent=[detail[@"parent"] isKindOfClass:NSDictionary.class]&&detail[@"parent"][@"path"]?detail[@"parent"][@"path"]:@"";
    NSString *origin=[detail[@"origin"] isKindOfClass:NSDictionary.class]&&detail[@"origin"][@"path"]?detail[@"origin"][@"path"]:@"";
    NSString *key=AOJSON(@[kind,actor[@"app"] ?: @"unknown",path,detail[@"protocol"] ?: @"",detail[@"remote"] ?: @"",parent,origin]);
    NSMutableDictionary *window=_connectionWindows[key];
    if(window&&now-[window[@"started"] doubleValue]<=AOConnectionWindow) {
        if(![window[@"count"] longLongValue])window[@"first"]=@(now);
        window[@"count"]=@([window[@"count"] longLongValue]+1);window[@"last"]=@(now);
        NSMutableOrderedSet *pids=window[@"pids"];
        if(pids.count<5&&[actor[@"pid"] intValue]>0)[pids addObject:actor[@"pid"]];
        return;
    }
    if(window)[self flushConnection:window];
    else if(_connectionWindows.count>=4096){[_store record:kind actor:actor source:@"networkstatistics" detail:detail priority:priority];return;}
    NSMutableDictionary *summary=[NSMutableDictionary new];
    for(NSString *name in @[@"remote",@"local",@"protocol",@"process_name",@"provider",@"ancestors"])if(detail[name])summary[name]=detail[name];
    if(parent.length)summary[@"parent"]=@{@"path":parent};
    if(origin.length)summary[@"origin"]=@{@"path":origin,@"app":detail[@"origin"][@"app"] ?: @""};
    _connectionWindows[key]=[@{@"started":@(now),@"count":@0,@"kind":kind,@"priority":@(priority),@"detail":summary,@"pids":[NSMutableOrderedSet new],
        @"actor":@{@"app":actor[@"app"] ?: @"unknown",@"path":path,@"pid":@0}} mutableCopy];
    [_store record:kind actor:actor source:@"networkstatistics" detail:detail priority:priority];
}
- (void)flushConnection:(NSDictionary *)window {
    long long count=[window[@"count"] longLongValue];if(count<1)return;
    NSMutableDictionary *detail=[window[@"detail"] mutableCopy];
    detail[@"merged"]=@YES;detail[@"window_seconds"]=@(AOConnectionWindow);detail[@"process_ids"]=[window[@"pids"] array];
    [_store record:window[@"kind"] actor:window[@"actor"] source:@"networkstatistics" detail:detail priority:[window[@"priority"] integerValue]
             first:[window[@"first"] doubleValue] last:[window[@"last"] doubleValue] count:count];
}
- (void)flushConnections:(BOOL)all {
    NSTimeInterval now=NSDate.date.timeIntervalSince1970;
    for(NSString *key in _connectionWindows.allKeys) {
        NSDictionary *window=_connectionWindows[key];
        if(!all&&now-[window[@"started"] doubleValue]<=AOConnectionWindow)continue;
        [self flushConnection:window];[_connectionWindows removeObjectForKey:key];
    }
}
// A file that was never seen is recorded as the baseline, present or absent.
// After that, a new digest is an event, including a file that appears.
- (void)checkSensitiveFiles {
    for(NSArray<NSString *> *entry in sensitiveFiles()){@autoreleasepool{
        if(self.stopping)return;
        NSString *category=entry[0],*path=entry[1];
        NSMutableDictionary *state=[sensitiveState(path) mutableCopy];
        NSString *signature=state[@"signature"];[state removeObjectForKey:@"signature"];
        if([_sensitiveSeen[path] isEqual:signature])continue;
        if([state[@"exists"] boolValue]){state[@"signature"]=signature;sensitiveDigest(path,state);[state removeObjectForKey:@"signature"];}
        NSString *key=[@"sensitive:" stringByAppendingString:path],*digest=state[@"sha256"];
        NSDictionary *old=[self fileQuery:@"SELECT fingerprint,detail FROM inventory WHERE path=?" arguments:@[key]].firstObject;
        if(old&&![old[@"fingerprint"] isEqual:digest]) {
            NSDictionary *previous=[old[@"detail"] isKindOfClass:NSString.class]?[NSJSONSerialization JSONObjectWithData:[old[@"detail"] dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil]:nil;
            [self fileRecord:@"sensitive_file_changed" actor:@{@"app":@"sensitive-file",@"path":path} source:@"file_poll"
                      detail:@{@"category":category,@"previous":previous ?: @{},@"current":state} priority:3];
        }
        if(!old||![old[@"fingerprint"] isEqual:digest]) {
            if(![self fileExecute:@"INSERT INTO inventory(path,fingerprint,detail,updated) VALUES(?,?,?,?) ON CONFLICT(path) DO UPDATE SET fingerprint=excluded.fingerprint,detail=excluded.detail,updated=excluded.updated" arguments:@[key,digest,AOJSON(state),@(NSDate.date.timeIntervalSince1970)]])continue;
        }
        _sensitiveSeen[path]=signature;
    }}
}
// tccd writes three lines for each permission check: the service, the
// processes involved and the decision. They share a message ID.
- (BOOL)consumePermissionLog:(NSString *)message {
    BOOL context=[message hasPrefix:@"AUTHREQ_CTX:"],attribution=[message hasPrefix:@"AUTHREQ_ATTRIBUTION:"],result=[message hasPrefix:@"AUTHREQ_RESULT:"];
    if(!context&&!attribution&&!result)return NO;
    NSString *identifier=logField(message,@"msgID=",@",");if(!identifier.length)return YES;
    NSTimeInterval now=NSDate.date.timeIntervalSince1970;
    if(_permissionRequests.count>512)[_permissionRequests removeAllObjects];
    NSMutableDictionary *request=_permissionRequests[identifier];
    if(!request){request=[@{@"at":@(now)} mutableCopy];_permissionRequests[identifier]=request;}
    if(context) {
        request[@"service"]=logField(message,@"service=",@",") ?: @"";
        request[@"preflight"]=@([logField(message,@"preflight=",@",") isEqual:@"yes"]);
    } else if(attribution) {
        for(NSString *role in @[@"requesting",@"accessing",@"responsible"]) {
            NSRange start=[message rangeOfString:[role stringByAppendingString:@"={TCCDProcess:"]];if(start.location==NSNotFound)continue;
            NSString *rest=[message substringFromIndex:NSMaxRange(start)];
            NSString *program=logField(rest,@"identifier=",@",}"),*binary=logField(rest,@"binary_path=",@"}");
            if(program.length)request[role]=@{@"identifier":program,@"path":binary ?: @"",@"pid":@([logField(rest,@"pid=",@",}") intValue])};
        }
    } else {
        [_permissionRequests removeObjectForKey:identifier];
        NSDictionary *subject=request[@"accessing"] ?: request[@"requesting"];
        NSString *service=request[@"service"];
        if(!subject||!service.length)return YES;
        int value=[logField(message,@"authValue=",@",") intValue];
        NSDictionary *responsible=request[@"responsible"];
        NSString *seen=AOJSON(@[service,subject[@"identifier"],subject[@"path"],@(value),responsible[@"path"] ?: @""]);
        if(_permissionSeen.count>4096)[_permissionSeen removeAllObjects];
        if(_permissionSeen[seen]&&now-[_permissionSeen[seen] doubleValue]<AOPermissionRepeat)return YES;
        _permissionSeen[seen]=@(now);
        NSMutableDictionary *detail=[@{@"service":service,@"auth_value":@(value),@"auth_reason":@([logField(message,@"authReason=",@",") intValue]),
            @"decision":@[@"denied",@"unknown",@"allowed",@"limited"][MAX(0,MIN(3,value))],@"preflight":request[@"preflight"] ?: @NO,
            @"evidence":@"System privacy decision; one row per program, service and outcome every six hours"} mutableCopy];
        for(NSString *role in @[@"requesting",@"responsible"]) {
            NSDictionary *other=request[role];
            if(other&&other!=subject&&![other[@"path"] isEqual:subject[@"path"]])detail[role]=@{@"identifier":other[@"identifier"],@"path":other[@"path"]};
        }
        [_store record:@"permission_decision" actor:@{@"app":subject[@"identifier"],@"path":subject[@"path"],@"pid":subject[@"pid"]} source:@"tcc" detail:detail priority:1];
    }
    return YES;
}
- (void)flushTraffic {
    for(NSDictionary *entry in _networkTraffic.allValues) {
        [_store record:@"network_bytes" actor:entry[@"actor"] source:@"networkstatistics" detail:@{@"remote":entry[@"remote"],@"protocol":entry[@"protocol"],@"rx_delta":entry[@"rx"],@"tx_delta":entry[@"tx"],@"samples":entry[@"samples"],@"interval_start":entry[@"first"],@"interval_end":entry[@"last"],@"aggregated_by_application":@NO,@"aggregated_by_executable":@YES,@"attribution_overflow":entry[@"overflow"]} priority:0 at:[entry[@"last"] doubleValue]];
    }
    [_networkTraffic removeAllObjects];
}
- (void)scanTaps {
    uint32_t count=0; CGError e=CGGetEventTapList(0,NULL,&count);
    if(e||count>4096) { [_store setSensor:@"input_taps" status:@"unavailable" detail:[NSString stringWithFormat:@"CGGetEventTapList failed: %d, count %u",e,count]]; return; }
    CGEventTapInformation *list=calloc(MAX(count+16,16),sizeof(*list)); uint32_t filled=0;
    e=CGGetEventTapList(count+16,list,&filled);
    if(e) { free(list); [_store setSensor:@"input_taps" status:@"unavailable" detail:@"Event tap enumeration failed"]; return; }
    NSMutableDictionary *current=[NSMutableDictionary new];
    for(uint32_t i=0;i<MIN(filled,count+16);i++) {
        CGEventTapInformation t=list[i];
        if(!t.enabled) continue;
        NSString *key=[NSString stringWithFormat:@"%d:%u",t.tappingProcess,t.eventTapID];
        NSMutableArray *types=[NSMutableArray new];
        if(t.eventsOfInterest&CGEventMaskBit(kCGEventKeyDown)) [types addObject:@"key_down"];
        if(t.eventsOfInterest&CGEventMaskBit(kCGEventKeyUp)) [types addObject:@"key_up"];
        if(t.eventsOfInterest&CGEventMaskBit(kCGEventFlagsChanged)) [types addObject:@"modifier_keys"];
        if(!types.count) continue;
        NSDictionary *detail=@{@"event_types":types,@"listen_only":@((t.options&kCGEventTapOptionListenOnly)!=0),@"tap_point":@(t.tapPoint),@"target_pid":@(t.processBeingTapped),@"evidence":@"registered input observer, not proof of recording keystroke values"};
        NSDictionary *actor=AOProcess(t.tappingProcess); current[key]=@{@"actor":actor,@"detail":detail};
        if(!_taps[key]) [_store record:@"keyboard_observer_active" actor:actor source:@"cg_event_tap_inventory" detail:detail priority:2];
        else if(![_taps[key][@"detail"] isEqual:detail]) [_store record:@"keyboard_observer_changed" actor:actor source:@"cg_event_tap_inventory" detail:detail priority:2];
    }
    free(list);
    for(NSString *key in _taps) if(!current[key]) [_store record:@"keyboard_observer_inactive" actor:_taps[key][@"actor"] source:@"cg_event_tap_inventory" detail:_taps[key][@"detail"] priority:1];
    _taps=current;
    [_store setSensor:@"input_taps" status:@"active" detail:@"CG event-tap registration inventory, 1 second reconciliation; not a per-keystroke audit"];
}
- (void)scanHID {
    io_iterator_t devices=0;
    kern_return_t kr=IOServiceGetMatchingServices(kIOMainPortDefault,IOServiceMatching("IOHIDDevice"),&devices);
    if(kr!=KERN_SUCCESS) { [_store setSensor:@"hid" status:@"unavailable" detail:@"Cannot enumerate HID registry"]; return; }
    NSMutableDictionary *current=[NSMutableDictionary new]; io_service_t device;
    while((device=IOIteratorNext(devices))) {
        CFTypeRef pairsRef=IORegistryEntryCreateCFProperty(device,CFSTR("DeviceUsagePairs"),kCFAllocatorDefault,0);
        NSArray *pairs=CFBridgingRelease(pairsRef); BOOL keyboard=NO,mouse=NO;
        if([pairs isKindOfClass:NSArray.class]) for(NSDictionary *pair in pairs) {
            if([pair[@"DeviceUsagePage"] intValue]==1 && [pair[@"DeviceUsage"] intValue]==6) keyboard=YES;
            if([pair[@"DeviceUsagePage"] intValue]==1 && ([pair[@"DeviceUsage"] intValue]==2 || [pair[@"DeviceUsage"] intValue]==1)) mouse=YES;
        }
        if(!keyboard&&!mouse) { IOObjectRelease(device); continue; }
        io_iterator_t children=0;
        if(IORegistryEntryCreateIterator(device,kIOServicePlane,kIORegistryIterateRecursively,&children)==KERN_SUCCESS) {
            io_registry_entry_t entry;
            while((entry=IOIteratorNext(children))) {
                NSString *creator=CFBridgingRelease(IORegistryEntryCreateCFProperty(entry,CFSTR("IOUserClientCreator"),kCFAllocatorDefault,0));
                if([creator isKindOfClass:NSString.class]) {
                    int pid=0; sscanf(creator.UTF8String,"pid %d",&pid);
                    uint64_t registryID=0; IORegistryEntryGetRegistryEntryID(entry,&registryID);
                    io_name_t className={0}; IOObjectGetClass(entry,className);
                    NSDictionary *detail=@{@"keyboard":@(keyboard),@"mouse":@(mouse),@"client_class":@(className),@"evidence":@"HID user-client attachment"};
                    NSString *key=[NSString stringWithFormat:@"%d:%llu",pid,registryID];
                    NSDictionary *actor=AOProcess(pid); current[key]=@{@"actor":actor,@"detail":detail};
                    if(!_hidClients[key]) [_store record:@"hid_access_active" actor:actor source:@"ioregistry" detail:detail priority:2];
                }
                IOObjectRelease(entry);
            }
            IOObjectRelease(children);
        }
        IOObjectRelease(device);
    }
    IOObjectRelease(devices);
    for(NSString *key in _hidClients) if(!current[key]) [_store record:@"hid_access_inactive" actor:_hidClients[key][@"actor"] source:@"ioregistry" detail:_hidClients[key][@"detail"] priority:1];
    _hidClients=current;
    [_store setSensor:@"hid" status:@"active" detail:@"Keyboard/mouse HID user-client attribution; 5 second reconciliation, complemented by optional ES audit"];
}
- (void)refreshAudio {
    NSArray *objects=audioIDs(kAudioObjectSystemObject,kAudioHardwarePropertyProcessObjectList,kAudioObjectPropertyScopeGlobal);
    NSSet *present=[NSSet setWithArray:objects];
    for(NSNumber *object in [_audioClients.allKeys copy]) if(![present containsObject:object]) {
        NSDictionary *old=_audioClients[object];
        if([old[@"active"] boolValue]) [_store record:@"audio_input_stopped" actor:old[@"actor"] source:@"coreaudio" detail:old[@"detail"] priority:1];
        [_audioClients removeObjectForKey:object];
        AudioObjectPropertyAddress a={kAudioProcessPropertyIsRunningInput,kAudioObjectPropertyScopeGlobal,kAudioObjectPropertyElementMain};
        id block=_audioListeners[object]; if(block) AudioObjectRemovePropertyListenerBlock(object.unsignedIntValue,&a,ObserverQueue,block);
        [_audioListeners removeObjectForKey:object];
    }
    for(NSNumber *object in objects) {
        [self updateAudio:object];
        if(!_audioListeners[object]) {
            __weak AOCollector *weak=self;
            AudioObjectPropertyListenerBlock b=^(UInt32 n,const AudioObjectPropertyAddress *addresses){ (void)n;(void)addresses; [weak updateAudio:object]; };
            AudioObjectPropertyAddress a={kAudioProcessPropertyIsRunningInput,kAudioObjectPropertyScopeGlobal,kAudioObjectPropertyElementMain};
            if(AudioObjectAddPropertyListenerBlock(object.unsignedIntValue,&a,ObserverQueue,b)==noErr) _audioListeners[object]=b;
        }
    }
}
- (void)updateAudio:(NSNumber *)object {
    AudioObjectID oid=object.unsignedIntValue; pid_t pid=audioNumber(oid,kAudioProcessPropertyPID);
    BOOL active=audioNumber(oid,kAudioProcessPropertyIsRunningInput)!=0;
    NSMutableDictionary *actor=[AOProcess(pid) mutableCopy]; NSString *bundle=audioString(oid,kAudioProcessPropertyBundleID); if(bundle.length) actor[@"app"]=bundle;
    NSMutableArray *devices=[NSMutableArray new];
    for(NSNumber *device in audioIDs(oid,kAudioProcessPropertyDevices,kAudioObjectPropertyScopeInput)) {
        [devices addObject:@{@"name":audioString(device.unsignedIntValue,kAudioObjectPropertyName),@"transport":@(audioNumber(device.unsignedIntValue,kAudioDevicePropertyTransportType))}];
    }
    NSDictionary *detail=@{@"devices":devices,@"evidence":@"Core Audio process has an active input stream; may be a virtual audio device"};
    NSDictionary *old=_audioClients[object];
    if(active && ![old[@"active"] boolValue]) [_store record:@"audio_input_started" actor:actor source:@"coreaudio" detail:detail priority:2];
    if(!active && [old[@"active"] boolValue]) [_store record:@"audio_input_stopped" actor:old[@"actor"] source:@"coreaudio" detail:old[@"detail"] priority:1];
    _audioClients[object]=@{@"active":@(active),@"actor":actor,@"detail":detail};
}
- (void)startLog {
    if([_store isKindOfClass:AOAgentStore.class]) {
        __weak AOCollector *weak=self;
        [(AOAgentStore *)_store readCaptureStream:^(NSData *data){[weak consumeLog:data];}];
        [_store setSensor:@"capture" status:@"active" detail:@"Screen and audio attribution through the authenticated local connection"];
        return;
    }
    if(_stopping||_logTask.running) return;
    NSTask *task=[NSTask new]; task.executableURL=[NSURL fileURLWithPath:@"/usr/bin/log"];
    // install-protected.sh gives the protected capture job the same predicate.
    NSString *predicate=@"(process == 'ControlCenter' AND category == 'sensor-indicators') OR (process == 'replayd' AND (eventMessage CONTAINS 'accepted client connection' OR eventMessage CONTAINS 'SLContentStream start:' OR eventMessage CONTAINS 'SLContentStream stop:')) OR (subsystem == 'com.apple.TCC' AND eventMessage BEGINSWITH 'AUTHREQ_')";
    task.arguments=@[@"stream",@"--style",@"ndjson",@"--level",@"info",@"--predicate",predicate];
    NSPipe *out=[NSPipe pipe],*err=[NSPipe pipe]; task.standardOutput=out; task.standardError=err;
    __weak AOCollector *weak=self;
    out.fileHandleForReading.readabilityHandler=^(NSFileHandle *h){
        NSData *data=h.availableData;
        if(!data.length) { h.readabilityHandler=nil; return; }
        dispatch_async(ObserverQueue,^{ [weak consumeLog:data]; });
    };
    err.fileHandleForReading.readabilityHandler=^(NSFileHandle *h){
        NSData *data=h.availableData;
        if(!data.length) { h.readabilityHandler=nil; return; }
        dispatch_async(ObserverQueue,^{
            AOCollector *s=weak; if(!s) return;
            NSString *msg=[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"unreadable log error";
            if(msg.length>512) msg=[msg substringToIndex:512];
            [s.store setSensor:@"capture" status:@"degraded" detail:msg];
        });
    };
    task.terminationHandler=^(NSTask *ended){
        dispatch_async(ObserverQueue,^{ AOCollector *s=weak; if(s&&!s.stopping) [s.store setSensor:@"capture" status:@"unavailable" detail:[NSString stringWithFormat:@"OS activity log exited with status %d; automatic retry in 10 seconds",ended.terminationStatus]]; });
    };
    NSError *error=nil;
    if([task launchAndReturnError:&error]) { _logTask=task; [_store setSensor:@"capture" status:@"active" detail:@"Streaming OS screen/camera/microphone attribution changes and replayd client PIDs; OS-version dependent parser"]; }
    else [_store setSensor:@"capture" status:@"unavailable" detail:error.localizedDescription ?: @"log stream launch failed"];
}
- (void)consumeLog:(NSData *)data {
    [_logBuffer appendData:data];
    if(_logBuffer.length>1024*1024) { [_logBuffer setLength:0]; _store.dropped++; [_store record:@"collection_gap" actor:@{@"app":@"activity-observer"} source:@"unified_log" detail:@{@"reason":@"line buffer exceeded 1 MiB"} priority:3]; return; }
    while(YES) {
        const void *p=memchr(_logBuffer.bytes,'\n',_logBuffer.length); if(!p) break;
        NSUInteger length=(const char *)p-(const char *)_logBuffer.bytes;
        NSData *line=[_logBuffer subdataWithRange:NSMakeRange(0,length)]; [_logBuffer replaceBytesInRange:NSMakeRange(0,length+1) withBytes:NULL length:0];
        NSDictionary *event=[NSJSONSerialization JSONObjectWithData:line options:0 error:nil]; if(![event isKindOfClass:NSDictionary.class]) continue;
        NSString *message=event[@"eventMessage"]; if(![message isKindOfClass:NSString.class]) continue;
        _lastLogRecord=NSDate.date.timeIntervalSince1970;
        if([self consumePermissionLog:message])continue;
        NSRange range=[message rangeOfString:@"Active activity attributions changed to "];
        if(range.location!=NSNotFound) {
            NSString *array=[message substringFromIndex:NSMaxRange(range)];
            NSArray *items=[NSJSONSerialization JSONObjectWithData:[array dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
            if(![items isKindOfClass:NSArray.class]) { _unknownLogs++; continue; }
            NSMutableSet *current=[NSMutableSet new];
            for(id item in items) if([item isKindOfClass:NSString.class]) [current addObject:item];
            for(NSString *item in current) if(![_captureAttributions containsObject:item]) [self attribution:item active:YES];
            for(NSString *item in _captureAttributions) if(![current containsObject:item]) [self attribution:item active:NO];
            _captureAttributions=current;
        } else if([message containsString:@"accepted client connection PID:"]) {
            NSRange r=[message rangeOfString:@"PID:"]; pid_t pid=[[message substringFromIndex:NSMaxRange(r)] intValue];
            NSDictionary *actor=AOProcess(pid);
            [_store record:@"screen_capture_client_connected" actor:actor source:@"replayd" detail:@{@"evidence":@"capture-service client connection; attribution events confirm use separately"} priority:1];
        } else if([message containsString:@"SLContentStream start:"]||[message containsString:@"SLContentStream stop:"]) {
            // Stream messages do not reliably identify a client. Keep them as
            // supporting system evidence instead of guessing the latest PID.
            [_store record:[message containsString:@" start:"]?@"capture_stream_started":@"capture_stream_stopped" actor:@{@"app":@"macOS.capture-service"} source:@"replayd" detail:@{@"evidence":@"OS capture stream transition; actor not present in this record"} priority:0];
        } else _unknownLogs++;
    }
}
- (void)attribution:(NSString *)item active:(BOOL)active {
    NSRange colon=[item rangeOfString:@":"]; if(colon.location==NSNotFound) return;
    NSString *prefix=[item substringToIndex:colon.location],*bundle=[item substringFromIndex:NSMaxRange(colon)];
    NSString *category=@{@"scr":@"screen",@"mic":@"microphone",@"cam":@"camera",@"aud":@"system_audio"}[prefix] ?: [@"privacy_" stringByAppendingString:prefix];
    NSMutableDictionary *actor=[@{@"app":bundle} mutableCopy];
    NSArray *apps=[NSRunningApplication runningApplicationsWithBundleIdentifier:bundle];
    if(apps.count==1) { NSRunningApplication *app=apps.firstObject; [actor addEntriesFromDictionary:AOProcess(app.processIdentifier)]; actor[@"app"]=bundle; }
    [_store record:[category stringByAppendingString:active?@"_started":@"_stopped"] actor:actor source:@"os_privacy_attribution" detail:@{@"evidence":@"OS active usage attribution",@"attribution":item} priority:active?2:1];
}
- (void)startFiles { [self replaceFileStream:fileWatchRoots(_roots)]; }
- (void)replaceFileStream:(NSArray *)roots {
    if(self.stopping)return;
    FSEventStreamContext context={0,(__bridge void *)self,NULL,NULL,NULL};
    FSEventStreamRef stream=FSEventStreamCreate(kCFAllocatorDefault,fileEvents,&context,(__bridge CFArrayRef)roots,kFSEventStreamEventIdSinceNow,1.0,kFSEventStreamCreateFlagUseCFTypes|kFSEventStreamCreateFlagFileEvents|kFSEventStreamCreateFlagWatchRoot);
    if(stream){
        FSEventStreamSetDispatchQueue(stream,_fileInputQueue);
        if(FSEventStreamStart(stream)){
            FSEventStreamRef previous=_fsStream;_fsStream=stream;self.watchRoots=roots;
            if(previous){FSEventStreamFlushSync(previous);FSEventStreamStop(previous);FSEventStreamInvalidate(previous);FSEventStreamRelease(previous);}
            [_store setSensor:@"install_update" status:@"active" detail:@"Filesystem events and persistent fingerprints; missing roots covered by their nearest existing ancestor"];
            return;
        }
        FSEventStreamInvalidate(stream);FSEventStreamRelease(stream);
    }
    [_store setSensor:@"install_update" status:_fsStream?@"degraded":@"unavailable" detail:@"FSEvents subscription failed; automatic retry"];
}
- (void)inventory {
    if(self.stopping||_inventoryRun)return;
    NSString *reason=_inventoryRecoveryPending?@"event_gap":_lastInventorySweep?@"periodic":@"startup";
    _inventoryRecoveryPending=NO;_lastInventorySweep=NSDate.date.timeIntervalSince1970;
    _inventoryRun=[@{@"reason":reason,@"available_roots":[NSMutableArray new],@"roots_scanned":@0,@"unavailable_roots":@0,@"absent_roots":@0,@"limited_roots":@0,@"read_errors":@0,@"known_paths_rechecked":@0,@"sensor_drops":@0} mutableCopy];
    __block uint64_t drops;dispatch_sync(ObserverQueue,^{drops=self.store.dropped;});_inventoryRun[@"sensor_drops_at_start"]=@(drops);
    _inventoryRootCursor=0;_knownInventoryCursor=0;_inventoryEnumerator=nil;_inventoryChecked=[NSMutableSet new];
    _knownInventory=[self fileQuery:@"SELECT path,detail FROM inventory" arguments:@[]];
}
- (void)inventoryStep {
    if(!_inventoryRun||self.stopping)return;
    NSUInteger visited=0,fingerprints=0;
    while(visited<256&&fingerprints<16&&_inventoryRootCursor<_roots.count){@autoreleasepool{
        NSString *root=_roots[_inventoryRootCursor];
        if(!_inventoryEnumerator){
            struct stat rootStat;if(lstat(root.fileSystemRepresentation,&rootStat)!=0){NSString *field=(errno==ENOENT||errno==ENOTDIR)?@"absent_roots":@"unavailable_roots";_inventoryRun[field]=@([_inventoryRun[field] unsignedIntegerValue]+1);_inventoryRootCursor++;continue;}
            [_inventoryRun[@"available_roots"] addObject:root.stringByResolvingSymlinksInPath];
            if([root.lastPathComponent isEqual:@"Cellar"]||[root.lastPathComponent isEqual:@"Application Support"]){_inventoryRootCursor++;continue;}
            _inventoryAppRoot=[root.lastPathComponent isEqual:@"Applications"];_inventoryRootEntries=0;
            __weak AOCollector *weak=self;
            _inventoryEnumerator=[NSFileManager.defaultManager enumeratorAtURL:[NSURL fileURLWithPath:root] includingPropertiesForKeys:@[NSURLIsDirectoryKey,NSURLIsExecutableKey,NSURLIsSymbolicLinkKey] options:NSDirectoryEnumerationSkipsHiddenFiles errorHandler:^BOOL(NSURL *url,NSError *error){AOCollector *s=weak;s.inventoryRun[@"read_errors"]=@([s.inventoryRun[@"read_errors"] unsignedIntegerValue]+1);return YES;}];
            _inventoryRun[@"roots_scanned"]=@([_inventoryRun[@"roots_scanned"] unsignedIntegerValue]+1);
        }
        NSURL *u=[_inventoryEnumerator nextObject];
        if(!u){_inventoryEnumerator=nil;_inventoryRootCursor++;continue;}
        visited++;
        if(++_inventoryRootEntries>20000){_inventoryRun[@"limited_roots"]=@([_inventoryRun[@"limited_roots"] unsignedIntegerValue]+1);_inventoryEnumerator=nil;_inventoryRootCursor++;continue;}
        if(cachePath(u.path)||[u.lastPathComponent isEqual:@"share"]||[u.lastPathComponent isEqual:@"node_modules"]){[_inventoryEnumerator skipDescendants];continue;}
        BOOL candidate=[u.pathExtension isEqual:@"app"];
        if(candidate)[_inventoryEnumerator skipDescendants];
        NSString *path=u.path.stringByResolvingSymlinksInPath;
        if(!candidate&&!_inventoryAppRoot){NSNumber *directory;[u getResourceValue:&directory forKey:NSURLIsDirectoryKey error:nil];candidate=!directory.boolValue&&(programFile(path)||[u.pathExtension isEqual:@"plist"]);}
        if(candidate){[self fingerprint:path changed:@[] initial:_baseline];[_inventoryChecked addObject:path];fingerprints++;}
    }}
    if(_inventoryRootCursor<_roots.count)return;
    // Recheck persisted paths on every startup and periodic scan, including
    // paths that vanished while the sensor was stopped. Work stays bounded per tick.
    NSUInteger checked=0;
    while(_knownInventoryCursor<_knownInventory.count&&checked<32){@autoreleasepool{
        NSString *path=_knownInventory[_knownInventoryCursor++][@"path"];
        if(![path isKindOfClass:NSString.class]||!path.isAbsolutePath||[_inventoryChecked containsObject:path])continue;
        // Previously executed apps can live outside the watched install roots.
        // Recheck those exact paths too, but do not call an unmounted volume a deletion.
        if([path hasPrefix:@"/Volumes/"]&&path.pathComponents.count>=3){
            NSString *volume=[NSString pathWithComponents:[path.pathComponents subarrayWithRange:NSMakeRange(0,3)]];
            if(![NSFileManager.defaultManager fileExistsAtPath:volume]){_inventoryRun[@"read_errors"]=@([_inventoryRun[@"read_errors"] unsignedIntegerValue]+1);continue;}
        }
        checked++;
        _inventoryRun[@"known_paths_rechecked"]=@([_inventoryRun[@"known_paths_rechecked"] unsignedIntegerValue]+1);
        struct stat st;if(lstat(path.fileSystemRepresentation,&st)!=0&&errno!=ENOENT&&errno!=ENOTDIR){_inventoryRun[@"read_errors"]=@([_inventoryRun[@"read_errors"] unsignedIntegerValue]+1);continue;}
        [self fingerprint:path changed:@[] initial:NO];
    }}
    if(_knownInventoryCursor<_knownInventory.count)return;
    if(_baseline){[self fileExecute:@"INSERT OR REPLACE INTO state(key,value) VALUES('baseline_complete','1')" arguments:@[]];_baseline=NO;}
    __block uint64_t drops;dispatch_sync(ObserverQueue,^{drops=self.store.dropped;});
    uint64_t before=[_inventoryRun[@"sensor_drops_at_start"] unsignedLongLongValue];
    _inventoryRun[@"sensor_drops"]=@(drops>before?drops-before:0);_inventoryRun[@"total_sensor_drops"]=@(drops);
    BOOL partial=[_inventoryRun[@"unavailable_roots"] unsignedIntegerValue]||[_inventoryRun[@"limited_roots"] unsignedIntegerValue]||[_inventoryRun[@"read_errors"] unsignedIntegerValue]||drops>before||_inventoryRecoveryPending;
    _inventoryRun[@"status"]=partial?@"partial":@"completed";_inventoryRun[@"scope"]=@"batched inventory scan and known-path recheck";_inventoryRun[@"known_path_limit"]=@NO;
    [_inventoryRun removeObjectForKey:@"available_roots"];
    [self fileRecord:@"filesystem_inventory_reconciled" actor:@{@"app":@"activity-observer"} source:@"inventory_reconciliation" detail:[_inventoryRun copy] priority:partial?3:2];
    _inventoryRun=nil;_knownInventory=nil;_inventoryChecked=nil;
}
- (void)processPaths {
    if(self.stopping)return;
    NSTimeInterval clock=NSProcessInfo.processInfo.systemUptime;
    if(clock<_nextFileProcess){
        if(!_fileProcessScheduled){_fileProcessScheduled=YES;dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)((_nextFileProcess-clock)*NSEC_PER_SEC)),_fileWorkQueue,^{self.fileProcessScheduled=NO;@autoreleasepool{[self processPaths];}});}return;
    }
    __block NSArray *batch;__block NSDictionary *overflow;__block NSUInteger queued;
    dispatch_sync(_fileInputQueue,^{queued=self.fileReady.entries.count;batch=[self.fileReady take:8];overflow=[self.fileReady takeOverflow];});
    [self reportFileOverflow:overflow queue:@"fingerprint" queued:queued flags:0 signals:0 observedAt:NSDate.date.timeIntervalSince1970];
    for(NSDictionary *entry in batch){@autoreleasepool{
        if(self.stopping)return;
        [self fingerprint:entry[@"path"] changed:[entry[@"changed"] array] initial:NO flags:[entry[@"flags"] unsignedIntValue] source:entry[@"source"]];
    }}
    NSTimeInterval elapsed=NSProcessInfo.processInfo.systemUptime-clock;
    _nextFileProcess=NSProcessInfo.processInfo.systemUptime+MIN(0.1,MAX(0.005,elapsed*4));
    __block BOOL more;dispatch_sync(_fileInputQueue,^{more=self.fileReady.entries.count>0||self.fileReady.dropped>0;});
    dispatch_source_t signal=_fileProcessSource;if(more&&signal)dispatch_source_merge_data(signal,1);
}
- (void)fingerprint:(NSString *)path changed:(NSArray *)changed initial:(BOOL)initial {
    [self fingerprint:path changed:changed initial:initial flags:0 source:@"inventory_reconciliation"];
}
- (void)fingerprint:(NSString *)path changed:(NSArray *)changed initial:(BOOL)initial flags:(unsigned)flags source:(NSString *)source {
    NSDictionary *old=[self fileQuery:@"SELECT fingerprint,detail FROM inventory WHERE path=?" arguments:@[path]].firstObject;
    if(![NSFileManager.defaultManager fileExistsAtPath:path]) {
        struct stat missing;
        if(old&&lstat(path.fileSystemRepresentation,&missing)!=0&&(errno==ENOENT||errno==ENOTDIR)) {
            [self fileRecord:@"program_removed" actor:AOApp(path) source:source detail:@{@"path":path} priority:2];
            if([self fileExecute:@"DELETE FROM inventory WHERE path=?" arguments:@[path]])dispatch_async(_fileInputQueue,^{[self.knownFilePaths removeObject:path];});
        }
        return;
    }
    NSDictionary *targetAttributes=[NSFileManager.defaultManager attributesOfItemAtPath:path error:nil];
    if(![targetAttributes[NSFileType] isEqual:NSFileTypeRegular]&&
       !([targetAttributes[NSFileType] isEqual:NSFileTypeDirectory]&&[path.pathExtension isEqual:@"app"]))return;
    NSMutableDictionary *details=[AOApp(path) mutableCopy]; NSString *binary=path;
    if([path.pathExtension isEqual:@"app"]) {
        NSDictionary *info=AOReadPlist([path stringByAppendingPathComponent:@"Contents/Info.plist"]);
        NSString *name=[info[@"CFBundleExecutable"] isKindOfClass:NSString.class]?info[@"CFBundleExecutable"]:nil;
        if(name.length && [name isEqual:name.lastPathComponent] && ![name isEqual:@"."] && ![name isEqual:@".."]){
            NSString *candidate=[path stringByAppendingPathComponent:[@"Contents/MacOS/" stringByAppendingString:name]];
            if([candidate.stringByResolvingSymlinksInPath hasPrefix:[path.stringByResolvingSymlinksInPath stringByAppendingString:@"/"]])binary=candidate;
        }
    }
    NSDictionary *attr=[NSFileManager.defaultManager attributesOfItemAtPath:binary error:nil];
    details[@"binary"]=binary; details[@"size"]=attr[NSFileSize] ?: @0; details[@"mtime"]=@([attr[NSFileModificationDate] timeIntervalSince1970]);
    SecStaticCodeRef code=NULL; CFDictionaryRef signing=NULL;
    if(SecStaticCodeCreateWithPath((__bridge CFURLRef)[NSURL fileURLWithPath:path],kSecCSDefaultFlags,&code)==errSecSuccess) {
        if(SecCodeCopySigningInformation(code,kSecCSSigningInformation,&signing)==errSecSuccess) {
            NSDictionary *s=CFBridgingRelease(signing);
            details[@"signing_identifier"]=s[(__bridge NSString *)kSecCodeInfoIdentifier] ?: @"";
            details[@"team_id"]=s[(__bridge NSString *)kSecCodeInfoTeamIdentifier] ?: @"";
            NSData *cd=s[(__bridge NSString *)kSecCodeInfoUnique]; if(cd) details[@"code_directory_fingerprint"]=AOHash(cd);
        }
        CFRelease(code);
    }
    // Small binaries and persistent configuration get a byte fingerprint. Large
    // signed binaries use the code-directory identity; changed resources are
    // independently reported even when the version and signing identity match.
    if([attr[NSFileSize] unsignedLongLongValue]<=1024*1024 && [attr[NSFileType] isEqual:NSFileTypeRegular]) {
        NSData *bytes=[NSData dataWithContentsOfFile:binary options:NSDataReadingMappedIfSafe error:nil]; if(bytes) details[@"sha256"]=AOHash(bytes);
    }
    NSString *encoded=AOJSON(details),*fingerprint=AOHash([encoded dataUsingEncoding:NSUTF8StringEncoding]);
    BOOL different=old && ![old[@"fingerprint"] isEqual:fingerprint];
    if((!initial||old) && (!old||different||changed.count)) {
        NSTimeInterval created=[attr[NSFileCreationDate] timeIntervalSince1970];
        NSDictionary *rootAttributes=[NSFileManager.defaultManager attributesOfItemAtPath:path error:nil];
        created=MAX(created,[rootAttributes[NSFileCreationDate] timeIntervalSince1970]);
        BOOL added=(flags&kFSEventStreamEventFlagItemCreated)&&created>=_observationStarted;
        NSString *kind=!old?(added?@"program_installed":@"program_first_seen"):different?@"program_updated":@"program_files_changed";
        NSMutableDictionary *event=[@{@"current":details,@"changed_paths":changed,@"fingerprint":fingerprint} mutableCopy];
        if(old) event[@"previous"]=[NSJSONSerialization JSONObjectWithData:[old[@"detail"] dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil] ?: @{};
        if(!old) {
            event[@"evidence"]=added?@"Created path observed during collection":@"First observation; installation time not established";
            event[@"file_created_event"]=@((flags&kFSEventStreamEventFlagItemCreated)!=0);event[@"filesystem_created_at"]=@(created);
            NSString *family=versionFamily(path);
            if(![family isEqual:path]&&[details[@"app"] containsString:@"."]) for(NSDictionary *row in [self fileQuery:@"SELECT path,detail FROM inventory" arguments:@[]]) {
                if([row[@"path"] isEqual:path]||![versionFamily(row[@"path"]) isEqual:family])continue;
                NSDictionary *peer=[NSJSONSerialization JSONObjectWithData:[row[@"detail"] dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
                if([peer[@"app"] isEqual:details[@"app"]]&&![peer[@"version"] isEqual:details[@"version"]]&&peer[@"version"]&&details[@"version"]) {
                    kind=@"program_version_observed";event[@"previous"]=peer;event[@"evidence"]=@"Different version observed in the same versioned program location; side-by-side copies may coexist";break;
                }
            }
        }
        [self fileRecord:kind actor:details source:source detail:event priority:2];
    }
    BOOL saved=[self fileExecute:@"INSERT INTO inventory(path,fingerprint,detail,updated) VALUES(?,?,?,?) ON CONFLICT(path) DO UPDATE SET fingerprint=excluded.fingerprint,detail=excluded.detail,updated=excluded.updated" arguments:@[path,fingerprint,encoded,@(NSDate.date.timeIntervalSince1970)]];
    if(saved)dispatch_async(_fileInputQueue,^{[self.knownFilePaths addObject:path];});
}
- (void)stop {
    self.stopping=YES;
    if(_fileTimer){dispatch_source_cancel(_fileTimer);_fileTimer=nil;}
    if(_sensitiveTimer){dispatch_source_cancel(_sensitiveTimer);_sensitiveTimer=nil;}
    if(_fileDrainSource){dispatch_source_cancel(_fileDrainSource);_fileDrainSource=nil;}
    if(_fileProcessSource){dispatch_source_cancel(_fileProcessSource);_fileProcessSource=nil;}
    for(dispatch_source_t t in _timers) dispatch_source_cancel(t); [_timers removeAllObjects];
    if(_logTask.running) [_logTask terminate];
    if(_fsStream) { FSEventStreamStop(_fsStream); FSEventStreamInvalidate(_fsStream); FSEventStreamRelease(_fsStream); _fsStream=NULL; }
    for(id object in _audioListeners) {
        BOOL system=[object isKindOfClass:NSString.class];
        AudioObjectPropertyAddress a={system?kAudioHardwarePropertyProcessObjectList:kAudioProcessPropertyIsRunningInput,kAudioObjectPropertyScopeGlobal,kAudioObjectPropertyElementMain};
        AudioObjectRemovePropertyListenerBlock(system?kAudioObjectSystemObject:[object unsignedIntValue],&a,ObserverQueue,_audioListeners[object]);
    }
    [_audioListeners removeAllObjects]; AONetworkStop();
    for(id observer in _workspaceObservers) [NSWorkspace.sharedWorkspace.notificationCenter removeObserver:observer];
    [_workspaceObservers removeAllObjects];
    [self flushTraffic];[self flushConnections:YES];
    [_store record:@"collector_stopped" actor:AOProcess(getpid()) source:@"collector" detail:@{} priority:2]; [_store flush]; [_store writeStatus];
}
@end
