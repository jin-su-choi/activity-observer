#import "Observer.h"
#import <AppKit/AppKit.h>
#import <signal.h>
#import <sys/file.h>
#import <fcntl.h>

static NSString *option(NSArray *args,NSString *name,NSString *fallback) {
    NSUInteger i=[args indexOfObject:name]; return i!=NSNotFound&&i+1<args.count?args[i+1]:fallback;
}
static void printJSON(id object) { puts(AOJSON(object).UTF8String); }
static BOOL checkStatus(NSMutableDictionary *status,NSString *directory,NSString *expected) {
    NSTimeInterval age=NSDate.date.timeIntervalSince1970-[status[@"heartbeat"] doubleValue];
    pid_t pid=[status[@"pid"] intValue];
    BOOL alive=pid>0&&(kill(pid,0)==0||errno==EPERM);
    BOOL signatureValid=YES;
    if(status[@"integrity_signature"]){
        NSDictionary *envelope=status[@"integrity_signature"];
        NSMutableDictionary *unsignedStatus=[status mutableCopy];
        [unsignedStatus removeObjectForKey:@"integrity_signature"];
        signatureValid=[AOJSON(unsignedStatus) isEqual:AOJSON(envelope[@"payload"])]&&
            [AOIntegrity verify:envelope publicFile:AOPublicKeyFile(directory) expectedFingerprint:expected error:nil];
        status[@"status_signature_valid"]=@(signatureValid);
    }
    status[@"heartbeat_age_seconds"]=@(age);
    status[@"collector_running"]=@(age>=0&&age<35&&alive);
    return signatureValid;
}
static int selfTest(void) {
    NSString *path=[NSTemporaryDirectory() stringByAppendingPathComponent:[@"activity-observer-check-" stringByAppendingString:NSUUID.UUID.UUIDString]];
    AOStore *store=nil; int result=1;
    @try {
        store=[[AOStore alloc] initWithDirectory:path maxBytes:3*1024*1024];
        NSDictionary *actor=@{@"app":@"fixture.app",@"pid":@123};
        for(int i=0;i<50;i++) [store record:@"screen_started" actor:actor source:@"fixture" detail:@{@"a":@1} priority:2];
        [store flush];
        NSArray *rows=[store query:@"SELECT id,count FROM events" arguments:@[]];
        if(rows.count!=1||[rows[0][@"count"] intValue]!=50) @throw @"aggregation failed";
        int64_t id1=[rows[0][@"id"] longLongValue]; if(![store checkpoint:id1]) @throw @"checkpoint failed";
        [store record:@"screen_started" actor:actor source:@"fixture" detail:@{@"a":@1} priority:2]; [store flush];
        NSDictionary *report=[store reportSinceCheckpoint:YES day:nil];
        if([report[@"patterns"] count]!=1 || [report[@"patterns"][0][@"count"] intValue]!=1) @throw @"checkpoint skipped new activity";
        if([store checkpoint:INT64_MAX]) @throw @"invalid checkpoint accepted";
        [store record:@"old" actor:actor source:@"fixture" detail:@{} priority:1 at:NSDate.date.timeIntervalSince1970-8*86400];
        NSString *oldDay=AODay(NSDate.date.timeIntervalSince1970-200*86400);
        [store record:@"ancient" actor:actor source:@"fixture" detail:@{} priority:1 at:NSDate.date.timeIntervalSince1970-200*86400];
        [store execute:@"INSERT INTO inventory(path,fingerprint,detail,updated) VALUES(?,?,?,?)" arguments:@[@"fixture-baseline",@"fingerprint",@"{}",@(NSDate.date.timeIntervalSince1970-200*86400)]];
        [store maintain];
        if([store query:@"SELECT id FROM events WHERE kind IN ('old','ancient')" arguments:@[]].count!=2) @throw @"age deleted events without capacity pressure";
        if(![store query:@"SELECT 1 FROM daily WHERE day=?" arguments:@[oldDay]].count) @throw @"age deleted statistics without capacity pressure";
        if(![store query:@"SELECT 1 FROM inventory WHERE path='fixture-baseline'" arguments:@[]].count) @throw @"age deleted inventory baseline";
        for(int batch=0;batch<12;batch++) {
            for(int i=0;i<250;i++) [store record:@"capacity" actor:actor source:@"fixture" detail:@{@"number":@(batch*250+i),@"padding":[@"x" stringByPaddingToLength:600 withString:@"x" startingAtIndex:0]} priority:0];
            [store maintain];
        }
        uint64_t bytes=AODirectoryBytes(path); if(bytes>3*1024*1024) @throw @"disk cap exceeded";
        if(!store.pruned||[store query:@"SELECT id FROM events WHERE kind IN ('old','ancient')" arguments:@[]].count) @throw @"capacity did not prune oldest events";
        uint64_t eventPruned=store.pruned,eventDropped=store.dropped;
        [store close];
        NSString *statisticsPath=[path stringByAppendingPathComponent:@"statistics"];
        store=[[AOStore alloc] initWithDirectory:statisticsPath maxBytes:3*1024*1024];
        for(int batch=0;batch<100&&!store.prunedStatistics;batch++) {
            if(![store execute:@"BEGIN IMMEDIATE" arguments:@[]]) @throw @"statistics fixture transaction failed";
            for(int i=0;i<20;i++) {
                int index=batch*20+i;
                NSString *name=[[NSString stringWithFormat:@"fixture-%d-",index] stringByPaddingToLength:600 withString:@"x" startingAtIndex:0];
                if(![store execute:@"INSERT INTO daily(day,app,kind,count,rx,tx) VALUES(?,?,?,1,0,0)" arguments:@[AODay(NSDate.date.timeIntervalSince1970-(5000-index)*86400),name,@"fixture"]]) @throw @"statistics fixture write failed";
            }
            if(![store execute:@"COMMIT" arguments:@[]]) @throw @"statistics fixture commit failed";
            [store maintain];
            if(batch==0&&[store query:@"SELECT 1 FROM daily" arguments:@[]].count!=20) @throw @"old statistics removed below capacity threshold";
        }
        uint64_t statisticsPruned=store.prunedStatistics;
        if(!statisticsPruned||AODirectoryBytes(statisticsPath)>3*1024*1024) @throw @"statistics capacity cleanup failed";
        [store close];store=[[AOStore alloc] initWithDirectory:statisticsPath maxBytes:3*1024*1024];
        if(store.prunedStatistics!=statisticsPruned) @throw @"statistics pruning counter not persisted";
        printJSON(@{@"self_test":@"passed",@"checks":@[@"aggregation",@"immutable review checkpoint",@"checkpoint validation",@"age-independent event/statistics retention",@"inventory baseline retention",@"oldest-first capacity cleanup",@"statistics capacity cleanup",@"disk budget under pressure"],@"data_bytes":@(bytes),@"pruned_rows":@(eventPruned),@"pruned_statistics_rows":@(statisticsPruned),@"dropped_events":@(eventDropped)});
        result=0;
    } @catch(id error) { printJSON(@{@"self_test":@"failed",@"error":[error description]}); }
    @finally { [store close]; [NSFileManager.defaultManager removeItemAtPath:path error:nil]; }
    return result;
}
static int integrityTest(void) {
    NSString *path=[NSTemporaryDirectory() stringByAppendingPathComponent:[@"activity-observer-integrity-" stringByAppendingString:NSUUID.UUID.UUIDString]];
    AOStore *store=nil;int result=1;
    @try {
        store=[[AOStore alloc] initWithDirectory:path maxBytes:3*1024*1024];
        AOIntegrity *key=[[AOIntegrity alloc] initWithPrivateDirectory:[path stringByAppendingPathComponent:@"private"] publicFile:[path stringByAppendingPathComponent:@"public-key.der"] create:YES];
        [store enableIntegrity:key];
        for(int i=0;i<5;i++)[store record:@"integrity_fixture" actor:@{@"app":@"fixture"} source:@"fixture" detail:@{@"i":@(i)} priority:2];
        [store flush];
        [store record:@"old_signed" actor:@{@"app":@"fixture"} source:@"fixture" detail:@{} priority:1 at:NSDate.date.timeIntervalSince1970-200*86400];
        [store maintain];
        if(![store query:@"SELECT id FROM events WHERE kind='old_signed'" arguments:@[]].count) @throw @"age deleted signed history without capacity pressure";
        if(![[store verifyIntegrity:key.fingerprint][@"valid"] boolValue])@throw @"valid chain rejected";
        NSDictionary *first=[store query:@"SELECT * FROM events ORDER BY id LIMIT 1" arguments:@[]].firstObject;
        [store execute:@"UPDATE events SET detail='tampered' WHERE id=?" arguments:@[first[@"id"]]];
        if([[store verifyIntegrity:key.fingerprint][@"valid"] boolValue])@throw @"content tampering not detected";
        [store execute:@"UPDATE events SET detail=? WHERE id=?" arguments:@[first[@"detail"],first[@"id"]]];
        if([[store verifyIntegrity:@"wrong-public-key"][@"valid"] boolValue])@throw @"key substitution accepted";
        NSString *original=[store query:@"SELECT value FROM state WHERE key='integrity_checkpoint'" arguments:@[]].firstObject[@"value"];
        NSMutableDictionary *envelope=[NSJSONSerialization JSONObjectWithData:[original dataUsingEncoding:NSUTF8StringEncoding] options:NSJSONReadingMutableContainers error:nil];
        envelope[@"payload"][@"head_id"]=@999999;
        [store execute:@"UPDATE state SET value=? WHERE key='integrity_checkpoint'" arguments:@[AOJSON(envelope)]];
        if([[store verifyIntegrity:key.fingerprint][@"valid"] boolValue])@throw @"checkpoint forgery accepted";
        [store execute:@"UPDATE state SET value=? WHERE key='integrity_checkpoint'" arguments:@[original]];
        for(int batch=0;batch<8;batch++){
            for(int i=0;i<200;i++)[store record:@"pressure" actor:@{@"app":@"fixture"} source:@"fixture" detail:@{@"i":@(batch*200+i),@"padding":[@"x" stringByPaddingToLength:600 withString:@"x" startingAtIndex:0]} priority:0];
            [store maintain];if(![[store verifyIntegrity:key.fingerprint][@"valid"] boolValue])@throw @"authorized retention broke chain";
        }
        [store record:@"tail" actor:@{@"app":@"fixture"} source:@"fixture" detail:@{} priority:2];[store flush];
        [store execute:@"DELETE FROM events WHERE id=(SELECT MAX(id) FROM events)" arguments:@[]];
        if([[store verifyIntegrity:key.fingerprint][@"valid"] boolValue])@throw @"tail deletion not detected";
        printJSON(@{@"integrity_self_test":@"passed",@"checks":@[@"valid chain",@"age-independent signed history",@"content tampering",@"public-key substitution",@"forged checkpoint",@"signed capacity boundary",@"tail deletion"]});result=0;
    }@catch(id e){printJSON(@{@"integrity_self_test":@"failed",@"error":[e description]});}
    @finally{[store close];[NSFileManager.defaultManager removeItemAtPath:path error:nil];}
    return result;
}

int main(int argc,const char *argv[]) {
    @autoreleasepool {
        NSArray<NSString *> *args=NSProcessInfo.processInfo.arguments;
        NSString *command=args.count>1?args[1]:@"help";
        if([command isEqual:@"self-test"]) return selfTest();
        if([command isEqual:@"integrity-self-test"]) return integrityTest();
        if([command isEqual:@"guard"]) return AORunGuard(option(args,@"--directory",AOProtectedDataDirectory()),(uid_t)[option(args,@"--user",@"0") intValue],AOProtectedExecutable());
        if([command isEqual:@"check-network-isolation"]) {
            BOOL blocked=AOInternetSocketsBlocked();
            printJSON(@{@"internet_sockets_blocked":@(blocked)});
            return blocked?0:77;
        }
        if([command isEqual:@"prepare-protected-key"]&&geteuid()==0&&args.count==2) {
            NSString *directory=AOProtectedDataDirectory();
            AOIntegrity *key=[[AOIntegrity alloc] initWithPrivateDirectory:[directory.stringByDeletingLastPathComponent stringByAppendingPathComponent:@"private"] publicFile:AOPublicKeyFile(directory) create:YES];
            printJSON(@{@"key_fingerprint":key.fingerprint});
            return 0;
        }
        if([command isEqual:@"reveal-in-finder"]&&args.count==3&&[args[2] isAbsolutePath]&&geteuid()!=0) {
            if(![NSFileManager.defaultManager fileExistsAtPath:args[2]])return 2;
            [NSWorkspace.sharedWorkspace activateFileViewerSelectingURLs:@[[NSURL fileURLWithPath:args[2]]]];
            return 0;
        }
        if([command isEqual:@"--version"]) { puts(AO_VERSION); return 0; }
        if([command isEqual:@"help"]||[command isEqual:@"--help"]) {
            puts("activity-observer " AO_VERSION "\n\nrun [--directory PATH] [--duration SECONDS] [--watch PATH]\nstatus [--directory PATH]\nverify [--expected-key SHA256] [--directory PATH]\nanchor [--expected-key SHA256]\nintegrity-checkpoint [--expected-key SHA256]\nreport [--unreviewed] [--day YYYY-MM-DD] [--directory PATH]\nevents [--after ID] [--through ID] [--limit N] [--directory PATH]\ncheckpoint --through ID [--directory PATH]\ncheck-network-isolation\nself-test\n\nDefault total managed storage limit: 1 GB (1,000,000,000 bytes).\nProtected mode uses a root-owned writer and a non-privileged sensor. No keyboard text, screenshots, audio samples or packet bodies are collected.");
            return 0;
        }
        if([command isEqual:@"activity-query"]) {
            NSMutableData *bytes=[NSMutableData new];
            while(bytes.length<=AOReadRequestMaxBytes) { NSData *part=[NSFileHandle.fileHandleWithStandardInput readDataUpToLength:MIN((NSUInteger)16384,AOReadRequestMaxBytes+1-bytes.length) error:nil];if(!part.length)break;[bytes appendData:part]; }
            id request=bytes.length<=AOReadRequestMaxBytes?[NSJSONSerialization JSONObjectWithData:bytes options:NSJSONReadingMutableContainers error:nil]:nil;
            if(![request isKindOfClass:NSMutableDictionary.class]){printJSON(@{@"error":@"invalid_query"});return 2;}
            request[@"op"]=@"activity-query";
            if([AOJSON(request) lengthOfBytesUsingEncoding:NSUTF8StringEncoding]>AOReadRequestMaxBytes){printJSON(@{@"error":@"query_request_too_large"});return 2;}
            NSDictionary *result=AORequestGuard(request);printJSON(result);
            if(result[@"error"]) return 2;
            return [AOIntegrity verify:result publicFile:AOPublicKeyFile(AOProtectedDataDirectory()) expectedFingerprint:option(args,@"--expected-key",nil) error:nil]?0:3;
        }
        if([command isEqual:@"anchor"]){NSDictionary *r=AORequestGuard(@{@"op":@"snapshot",@"fresh":@([args containsObject:@"--fresh"])});printJSON(r);if(r[@"error"])return 2;return [AOIntegrity verify:r publicFile:AOPublicKeyFile(AOProtectedDataDirectory()) expectedFingerprint:option(args,@"--expected-key",nil) error:nil]?0:3;}
        BOOL agent=[command isEqual:@"agent"];
        if(agent) {
            // The LaunchAgent is registered in each GUI domain; only its configured user runs it.
            if(geteuid()==0||geteuid()!=(uid_t)[option(args,@"--user",@"0") intValue])return 0;
            if(!AOInternetSocketsBlocked()){puts("Sensor requires its network isolation policy.");return 77;}
        }
        NSString *directory=agent?AOProtectedDataDirectory():option(args,@"--directory",AODefaultDataDirectory());
        BOOL protected=[directory.stringByStandardizingPath isEqual:AOProtectedDataDirectory().stringByStandardizingPath];
        if(protected&&!agent&&[@[@"report",@"events",@"verify",@"integrity-checkpoint"] containsObject:command]){
            NSMutableDictionary *request=[@{@"op":command} mutableCopy];
            if([args containsObject:@"--after"])request[@"after"]=@([option(args,@"--after",@"0") longLongValue]);
            if([args containsObject:@"--through"])request[@"through"]=@([option(args,@"--through",@"0") longLongValue]);
            if([args containsObject:@"--limit"])request[@"limit"]=@([option(args,@"--limit",@"100") intValue]);
            if([args containsObject:@"--day"])request[@"day"]=option(args,@"--day",nil);
            if([args containsObject:@"--expected-key"])request[@"expected_key"]=option(args,@"--expected-key",nil);
            NSDictionary *reply=AORequestGuard(request);
            printJSON(reply);
            if(reply[@"error"]) return 2;
            if([command isEqual:@"integrity-checkpoint"]) {
                return [AOIntegrity verify:reply publicFile:AOPublicKeyFile(directory) expectedFingerprint:option(args,@"--expected-key",nil) error:nil]?0:3;
            }
            return [command isEqual:@"verify"]&&![reply[@"valid"] boolValue]?3:0;
        }
        if(protected&&[command isEqual:@"monitor-context"]) {
            NSDictionary *result=AORequestGuard(@{@"op":@"monitor-context"});
            if(result[@"error"]){printJSON(result);return 2;}
            NSMutableDictionary *status=[result[@"status"] mutableCopy];
            NSDictionary *anchor=result[@"anchor"];
            NSString *expected=option(args,@"--expected-key",nil);
            if(![status isKindOfClass:NSDictionary.class] || !status[@"integrity_signature"] ||
               !checkStatus(status,directory,expected) ||
               ![AOIntegrity verify:anchor publicFile:AOPublicKeyFile(directory) expectedFingerprint:expected error:nil]) {
                printJSON(@{@"error":@"monitor_context_signature_invalid"});return 3;
            }
            printJSON(@{@"status":status,@"anchor":anchor});return 0;
        }
        if(protected&&[command isEqual:@"checkpoint"]){printJSON(@{@"error":@"protected_mode_uses_external_review_anchors",@"next_step":@"Keep the signed anchor in the review chat; use report --after its head_id."});return 77;}
        if(!protected&&![command isEqual:@"run"] && ![NSFileManager.defaultManager fileExistsAtPath:[directory stringByAppendingPathComponent:@"events.sqlite"]]) { printJSON(@{@"error":@"collector_not_initialized",@"directory":directory}); return 2; }
        if([command isEqual:@"status"]) {
            BOOL installedCheck=[args containsObject:@"--protected-file"];
            if(installedCheck&&(!protected||geteuid()!=0)){printJSON(@{@"error":@"protected_status_requires_root"});return 77;}
            BOOL broker=protected&&!installedCheck;
            NSData *data=broker?nil:[NSData dataWithContentsOfFile:[directory stringByAppendingPathComponent:@"status.json"]];
            NSMutableDictionary *status=broker?[AORequestGuard(@{@"op":@"status"}) mutableCopy]:data?[[NSJSONSerialization JSONObjectWithData:data options:NSJSONReadingMutableContainers error:nil] mutableCopy]:[NSMutableDictionary new];
            if(status[@"error"]){printJSON(status);return 2;}
            if(installedCheck&&!status[@"integrity_signature"]){printJSON(@{@"error":@"signed_status_not_ready"});return 2;}
            BOOL signatureValid=checkStatus(status,directory,option(args,@"--expected-key",nil));
            printJSON(status); return !signatureValid?3:[status[@"collector_running"] boolValue]?0:2;
        }
        AOStore *store=nil;
        ObserverQueue=dispatch_queue_create("local.activity-observer.collector",dispatch_queue_attr_make_with_autorelease_frequency(dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL,QOS_CLASS_UTILITY,0),DISPATCH_AUTORELEASE_FREQUENCY_WORK_ITEM));
        uint64_t maxBytes=[args containsObject:@"--max-mb"]?[option(args,@"--max-mb",@"0") longLongValue]*1024*1024:AODefaultMaxDataBytes;
        @try { store=agent?[[AOAgentStore alloc] initWithProtectedDirectory:directory]:[[AOStore alloc] initWithDirectory:directory maxBytes:maxBytes readOnly:protected&&geteuid()!=0]; }
        @catch(NSException *e) { printJSON(@{@"error":e.reason ?: @"database open failed"}); return 2; }
        if(agent)[store setSensor:@"sensor_network_isolation" status:@"active" detail:@"IPv4 and IPv6 TCP/UDP connect and bind denied"];
        if([command isEqual:@"verify"]){NSDictionary *r=[store verifyIntegrity:option(args,@"--expected-key",nil)];printJSON(r);[store close];return [r[@"valid"] boolValue]?0:3;}
        if([command isEqual:@"report"]) {
            NSDictionary *report=[args containsObject:@"--after"]?[store reportAfterID:[option(args,@"--after",@"0") longLongValue] day:option(args,@"--day",nil)]:[store reportSinceCheckpoint:[args containsObject:@"--unreviewed"] day:option(args,@"--day",nil)];
            printJSON(report); [store close]; return report[@"error"]?3:0;
        }
        if([command isEqual:@"events"]) {
            long long after=[option(args,@"--after",@"0") longLongValue],through=[option(args,@"--through",@(INT64_MAX).stringValue) longLongValue];
            long long limit=MAX(1,MIN([option(args,@"--limit",@"500") longLongValue],1000));
            NSArray *rows=[store query:@"SELECT * FROM events WHERE id>? AND id<=? ORDER BY id LIMIT ?" arguments:@[@(after),@(through),@(limit)]];
            printJSON(@{@"events":rows,@"next_after":rows.lastObject[@"id"] ?: @(after),@"through":@(through)}); [store close]; return 0;
        }
        if([command isEqual:@"checkpoint"]) {
            BOOL ok=[store checkpoint:[option(args,@"--through",@"-1") longLongValue]];
            printJSON(@{@"checkpoint_saved":@(ok)}); [store close]; return ok?0:2;
        }
        if(![command isEqual:@"run"]&&!agent) { printJSON(@{@"error":@"unknown command"}); [store close]; return 2; }
        if(protected&&!agent){printJSON(@{@"error":@"use_protected_guard"});[store close];return 77;}
        int lockfd=agent?-1:open([directory stringByAppendingPathComponent:@"collector.lock"].fileSystemRepresentation,O_CREAT|O_RDWR,0600);
        if(!agent&&(lockfd<0||flock(lockfd,LOCK_EX|LOCK_NB)!=0)) { printJSON(@{@"error":@"collector_already_running"}); [store close]; return 2; }
        NSMutableArray *roots=[NSMutableArray new];
        NSString *watch=agent?nil:option(args,@"--watch",nil);
        NSArray *candidates=watch?@[watch]:@[@"/Applications",[NSHomeDirectory() stringByAppendingPathComponent:@"Applications"],@"/Library/LaunchAgents",@"/Library/LaunchDaemons",@"/Library/PrivilegedHelperTools",[NSHomeDirectory() stringByAppendingPathComponent:@"Library/LaunchAgents"],@"/opt/homebrew/bin",@"/opt/homebrew/Cellar",@"/usr/local/bin",[NSHomeDirectory() stringByAppendingPathComponent:@".local"],[NSHomeDirectory() stringByAppendingPathComponent:@"Library/Application Support"]];
        [roots addObjectsFromArray:candidates];
        AOCollector *collector=[[AOCollector alloc] initWithStore:store roots:roots];
        static NSMutableArray *signals; signals=[NSMutableArray new];
        for(NSNumber *number in @[@(SIGTERM),@(SIGINT)]) {
            signal(number.intValue,SIG_IGN);
            dispatch_source_t s=dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL,number.intValue,0,ObserverQueue);
            dispatch_source_set_event_handler(s,^{ [collector stop]; [store close]; close(lockfd); exit(0); }); dispatch_resume(s); [signals addObject:s];
        }
        signal(SIGUSR1,SIG_IGN);
        dispatch_source_t flush=dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL,SIGUSR1,0,ObserverQueue);
        dispatch_source_set_event_handler(flush,^{ [store flush]; [store writeStatus]; }); dispatch_resume(flush); [signals addObject:flush];
        dispatch_async(ObserverQueue,^{ [collector start]; });
        double duration=agent?0:[option(args,@"--duration",@"0") doubleValue];
        if(duration>0) dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(duration*NSEC_PER_SEC)),ObserverQueue,^{ [collector stop]; [store close]; close(lockfd); exit(0); });
        CFRunLoopRun();
    }
}
