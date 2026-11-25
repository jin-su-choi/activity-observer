#import "FileHistory.h"

@interface AOHistoryRead : NSObject
@property NSArray<NSString *> *roots;
@property NSSet<NSString *> *known;
@property NSMutableOrderedSet<NSString *> *paths;
@property FSEventStreamEventId after, through;
@property NSUInteger bytes;
@property BOOL ended, limited, gap;
@property dispatch_semaphore_t done;
@end
@implementation AOHistoryRead
@end

static BOOL inScope(NSString *path, AOHistoryRead *read) {
    for(NSString *root in read.roots){
        if(![path isEqual:root] && ![path hasPrefix:[root stringByAppendingString:@"/"]])continue;
        // Broad discovery roots also contain private app data. Only keep
        // paths in application bundles or previously inventoried programs there.
        if([root hasSuffix:@"/Library/Application Support"] || [root hasSuffix:@"/.local"]){
            return [read.known containsObject:path] || [path.pathExtension isEqual:@"app"] ||
                   [path containsString:@".app/"];
        }
        return YES;
    }
    return NO;
}

static void historyEvents(ConstFSEventStreamRef stream, void *context, size_t count, void *raw,
                          const FSEventStreamEventFlags flags[], const FSEventStreamEventId ids[]) {
    AOHistoryRead *read=(__bridge AOHistoryRead *)context;
    NSArray *paths=(__bridge NSArray *)raw;
    for(size_t i=0;i<count&&!read.ended;i++){@autoreleasepool{
        if(flags[i]&kFSEventStreamEventFlagHistoryDone){
            read.ended=YES;dispatch_semaphore_signal(read.done);break;
        }
        if(flags[i]&(kFSEventStreamEventFlagMustScanSubDirs|kFSEventStreamEventFlagUserDropped|
                     kFSEventStreamEventFlagKernelDropped|kFSEventStreamEventFlagEventIdsWrapped|
                     kFSEventStreamEventFlagRootChanged)){
            read.gap=YES;continue;
        }
        if(ids[i]<=read.after || ids[i]>read.through)continue;
        NSString *path=paths[i];
        if(!inScope(path,read)||[read.paths containsObject:path])continue;
        NSUInteger cost=128+path.length*2;
        if(read.paths.count>=16384 || read.bytes+cost>4*1024*1024){
            read.limited=YES;read.ended=YES;dispatch_semaphore_signal(read.done);break;
        }
        if(path.length>2048){read.limited=YES;continue;} // Writer's per-string limit.
        [read.paths addObject:path];read.bytes+=cost;
    }}
}

void AOReadFileHistory(FSEventStreamEventId after,FSEventStreamEventId through,
                       NSArray<NSString *> *roots,NSSet<NSString *> *known,
                       void (^emit)(NSString *,NSDictionary *)) {
    AOHistoryRead *read=[AOHistoryRead new];read.after=after;read.through=through;
    read.roots=roots;read.known=known;read.paths=[NSMutableOrderedSet new];
    read.done=dispatch_semaphore_create(0);
    NSString *state=@"unavailable";
    if(after && through>=after && roots.count){
        FSEventStreamContext ctx={0,(__bridge void *)read,NULL,NULL,NULL};
        FSEventStreamRef stream=FSEventStreamCreate(NULL,historyEvents,&ctx,(__bridge CFArrayRef)roots,after,0.1,
            kFSEventStreamCreateFlagFileEvents|kFSEventStreamCreateFlagUseCFTypes|kFSEventStreamCreateFlagFullHistory);
        if(stream){
            dispatch_queue_t queue=dispatch_queue_create("local.activity-observer.files.history.delivery",DISPATCH_QUEUE_SERIAL);
            FSEventStreamSetDispatchQueue(stream,queue);
            if(FSEventStreamStart(stream)){
                long timedOut=dispatch_semaphore_wait(read.done,dispatch_time(DISPATCH_TIME_NOW,12*NSEC_PER_SEC));
                FSEventStreamStop(stream);
                FSEventStreamInvalidate(stream);
                dispatch_sync(queue, ^{});
                state=timedOut?@"timeout":read.limited?@"limited":read.gap?@"history_gap":@"history_done";
            }else FSEventStreamInvalidate(stream);
            FSEventStreamRelease(stream);
        }
    }
    NSString *run=NSUUID.UUID.UUIDString;
    NSMutableArray *chunk=[NSMutableArray new];
    NSUInteger encodedBytes=0, sent=0;
    for(NSString *path in read.paths){@autoreleasepool{
        // Account for JSON escaping; stay below the writer's 8 KiB detail cap.
        NSUInteger cost=[NSJSONSerialization dataWithJSONObject:@[path] options:0 error:nil].length;
        if(cost>7600){state=@"limited";continue;}
        if(chunk.count && (chunk.count>=48 || encodedBytes+cost>7600)){
            emit(@"filesystem_history_paths",@{@"run":run,@"paths":[chunk copy]});
            [chunk removeAllObjects];encodedBytes=0;
        }
        [chunk addObject:path];encodedBytes+=cost;sent++;
    }}
    if(chunk.count)emit(@"filesystem_history_paths",@{@"run":run,@"paths":[chunk copy]});
    emit(@"filesystem_history_replay",@{@"run":run,@"status":state,@"after_event_id":@(after),
            @"through_event_id":@(through),@"path_hints":@(sent),@"historical_operations_verified":@NO});
}
