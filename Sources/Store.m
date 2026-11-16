#import "Observer.h"
#import <CommonCrypto/CommonDigest.h>
#import <Security/Security.h>
#import <libproc.h>
#import <sys/resource.h>
#import <mach/mach.h>
#import <fcntl.h>
#import <sys/stat.h>

dispatch_queue_t ObserverQueue;
static int replaceStatusFile(NSString *path,NSData *bytes) {
    if(!bytes.length)return EINVAL;
    // Stage alongside the destination so the writer needs no access to a
    // system temporary directory. Readers see one complete signed status.
    NSString *name=[path stringByAppendingString:@".XXXXXX"];
    char *temporary=strdup(name.fileSystemRepresentation);
    if(!temporary)return ENOMEM;
    int fd=mkstemp(temporary);
    int error=fd<0?errno:0;
    if(fd>=0) {
        const uint8_t *data=bytes.bytes;
        NSUInteger offset=0;
        while(offset<bytes.length) {
            ssize_t written=write(fd,data+offset,bytes.length-offset);
            if(written<0&&errno==EINTR)continue;
            if(written<=0){error=written<0?errno:EIO;break;}
            offset+=(NSUInteger)written;
        }
        if(close(fd)!=0&&!error)error=errno;
        if(!error&&rename(temporary,path.fileSystemRepresentation)!=0)error=errno;
        if(error)unlink(temporary);
    }
    free(temporary);
    return error;
}
static id cleanJSON(id value, unsigned depth) {
    if (depth > 5) return @"[depth limited]";
    if ([value isKindOfClass:NSString.class]) return [value length] > 2048 ? [value substringToIndex:2048] : value;
    if ([value isKindOfClass:NSNumber.class] || value == NSNull.null) return value;
    if ([value isKindOfClass:NSArray.class]) {
        NSMutableArray *a = [NSMutableArray new];
        for (id v in value) { if (a.count == 64) break; [a addObject:cleanJSON(v, depth + 1)]; }
        return a;
    }
    if ([value isKindOfClass:NSDictionary.class]) {
        NSMutableDictionary *d = [NSMutableDictionary new];
        for (id k in value) { if (d.count == 64) break; d[[k description]] = cleanJSON(value[k], depth + 1); }
        return d;
    }
    return [value description] ?: @"";
}
NSString *AOJSON(id object) {
    NSData *d = [NSJSONSerialization dataWithJSONObject:object options:NSJSONWritingSortedKeys error:nil];
    return d ? [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] : @"{}";
}
// Days follow the Mac's time zone. localtime_r tracks a change of the system
// zone without a restart, so a record's day is the local day when it was made.
NSString *AODay(NSTimeInterval time) {
    time_t seconds = (time_t)floor(time);
    struct tm local;
    if (!localtime_r(&seconds, &local)) gmtime_r(&seconds, &local);
    return [NSString stringWithFormat:@"%04d-%02d-%02d", local.tm_year + 1900, local.tm_mon + 1, local.tm_mday];
}
NSString *AOTimeZoneName(void) {
    [NSTimeZone resetSystemTimeZone];
    return NSTimeZone.systemTimeZone.name ?: @"UTC";
}
NSString *AOHash(NSData *data) {
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *s = [NSMutableString new];
    for (unsigned i = 0; i < sizeof(digest); i++) [s appendFormat:@"%02x", digest[i]];
    return s;
}
NSDictionary *AOReadPlist(NSString *path) {
    int fd=open(path.fileSystemRepresentation,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);if(fd<0)return @{};
    struct stat attributes;if(fstat(fd,&attributes)!=0||!S_ISREG(attributes.st_mode)||attributes.st_size<0||attributes.st_size>512*1024){close(fd);return @{};}
    NSMutableData *data=[NSMutableData dataWithLength:(NSUInteger)attributes.st_size+1];ssize_t length=read(fd,data.mutableBytes,data.length);close(fd);
    if(length<0||length>512*1024)return @{};data.length=(NSUInteger)length;
    id value=data?[NSPropertyListSerialization propertyListWithData:data options:NSPropertyListImmutable format:NULL error:nil]:nil;
    return [value isKindOfClass:NSDictionary.class]?value:@{};
}
NSDictionary *AOApp(NSString *path) {
    NSString *bundlePath = nil;
    for (NSString *p = path; p.length > 1; p = p.stringByDeletingLastPathComponent) {
        if ([p.pathExtension isEqualToString:@"app"]) bundlePath = p;
    }
    NSDictionary *info = bundlePath ? AOReadPlist([bundlePath stringByAppendingPathComponent:@"Contents/Info.plist"]) : nil;
    NSString *identifier=[info[@"CFBundleIdentifier"] isKindOfClass:NSString.class]?info[@"CFBundleIdentifier"]:nil;
    if(identifier.length>1024)identifier=[identifier substringToIndex:1024];
    NSMutableDictionary *d = [@{@"path": path ?: @"", @"app": identifier ?: bundlePath.lastPathComponent ?: path.lastPathComponent ?: @"unknown"} mutableCopy];
    if (bundlePath) d[@"bundle_path"] = bundlePath;
    for(NSString *key in @[@"CFBundleShortVersionString",@"CFBundleVersion"]){
        id value=info[key];if([value isKindOfClass:NSString.class]||[value isKindOfClass:NSNumber.class]){
            NSString *text=[value description];if(text.length>1024)text=[text substringToIndex:1024];d[[key isEqual:@"CFBundleVersion"]?@"build":@"version"]=text;
        }
    }
    return d;
}
NSDictionary *AOProcess(pid_t pid) {
    char path[PROC_PIDPATHINFO_MAXSIZE] = {0};
    proc_pidpath(pid, path, sizeof(path));
    NSMutableDictionary *d = [AOApp(@(path)) mutableCopy];
    d[@"pid"] = @(pid);
    struct proc_bsdinfo b = {0};
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &b, sizeof(b)) == sizeof(b)) {
        d[@"ppid"] = @(b.pbi_ppid);
        d[@"process_start"] = @(b.pbi_start_tvsec+b.pbi_start_tvusec/1000000.0);
        if (!path[0]) d[@"app"] = @(b.pbi_name);
    }
    return d;
}
uint64_t AODirectoryBytes(NSString *path) {
    uint64_t total = 0;
    NSDirectoryEnumerator *e = [NSFileManager.defaultManager enumeratorAtURL:[NSURL fileURLWithPath:path] includingPropertiesForKeys:@[NSURLIsRegularFileKey, NSURLFileSizeKey] options:0 errorHandler:nil];
    for (NSURL *u in e) {
        NSNumber *regular, *size;
        [u getResourceValue:&regular forKey:NSURLIsRegularFileKey error:nil];
        if (regular.boolValue) { [u getResourceValue:&size forKey:NSURLFileSizeKey error:nil]; total += size.unsignedLongLongValue; }
    }
    return total;
}

@implementation AOStore {
    sqlite3 *_db;
    NSMutableDictionary<NSString *, NSMutableDictionary *> *_pending;
    NSTimeInterval _lastMaintenance;
    double _previousCPU;
    NSTimeInterval _previousSample;
    double _lastCPUPercent;
    uint64_t _unreviewedPruned;
    BOOL _readOnly;
    AOIntegrity *_integrity;
    NSString *_headHash;
    NSString *_boundaryHash;
    int64_t _headID;
    int64_t _boundaryID;
    NSTimeInterval _sealedStarted;
    int _databaseResult;
    NSDictionary *_lastStorageError;
}
- (instancetype)initWithDirectory:(NSString *)directory maxBytes:(uint64_t)maxBytes {
    return [self initWithDirectory:directory maxBytes:maxBytes readOnly:NO];
}
- (instancetype)initWithDirectory:(NSString *)directory maxBytes:(uint64_t)maxBytes readOnly:(BOOL)readOnly {
    if (!(self = [super init])) return nil;
    _directory = directory.stringByStandardizingPath;
    _databasePath = [_directory stringByAppendingPathComponent:@"events.sqlite"];
    _maxBytes = MAX(maxBytes, 3 * 1024 * 1024);
    _started = NSDate.date.timeIntervalSince1970;
    _pending = [NSMutableDictionary new]; _health = [NSMutableDictionary new];
    _readOnly=readOnly;
    if(!readOnly) [NSFileManager.defaultManager createDirectoryAtPath:_directory withIntermediateDirectories:YES attributes:@{NSFilePosixPermissions:@0700} error:nil];
    if (sqlite3_open_v2(_databasePath.fileSystemRepresentation, &_db, (readOnly?SQLITE_OPEN_READONLY:(SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE)) | SQLITE_OPEN_FULLMUTEX, NULL) != SQLITE_OK) @throw [NSException exceptionWithName:@"Database" reason:@(sqlite3_errmsg(_db)) userInfo:nil];
    if(!readOnly) chmod(_databasePath.fileSystemRepresentation, 0600);
    sqlite3_busy_timeout(_db, readOnly?3000:250);
    if(readOnly) return self;
    // A rollback journal is bounded by the database size. One-third of the total
    // budget leaves room for the journal, status, inventory, and atomic replacements.
    if(![self execute:@"PRAGMA page_size=4096; PRAGMA auto_vacuum=INCREMENTAL; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA cache_size=-2048; PRAGMA temp_store=MEMORY;" arguments:@[]])
        @throw [NSException exceptionWithName:@"Database" reason:@"Could not configure the storage journal" userInfo:nil];
    uint64_t occupied=AODirectoryBytes(_directory);
    for(NSString *name in @[@"events.sqlite",@"events.sqlite-journal",@"status.json"]){
        uint64_t size=[[NSFileManager.defaultManager attributesOfItemAtPath:[_directory stringByAppendingPathComponent:name] error:nil][NSFileSize] unsignedLongLongValue];occupied=occupied>=size?occupied-size:0;
    }
    uint64_t reserve=MIN(8*1024*1024,_maxBytes/16);
    if(occupied+reserve>=_maxBytes)@throw [NSException exceptionWithName:@"StorageBudget" reason:@"Existing managed files exhaust the storage budget" userInfo:nil];
    uint64_t databaseBudget=MIN(_maxBytes/3,(_maxBytes-occupied-reserve)/2);
    [self execute:[NSString stringWithFormat:@"PRAGMA max_page_count=%llu", databaseBudget / 4096] arguments:@[]];
    if(![self execute:@"CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT,first REAL NOT NULL,last REAL NOT NULL,day TEXT NOT NULL,kind TEXT NOT NULL,app TEXT NOT NULL,pid INTEGER,path TEXT,source TEXT,detail TEXT,priority INTEGER,count INTEGER NOT NULL); CREATE INDEX IF NOT EXISTS events_day ON events(day,id); CREATE INDEX IF NOT EXISTS events_last ON events(last); CREATE TABLE IF NOT EXISTS daily(day TEXT,app TEXT,kind TEXT,count INTEGER,rx INTEGER,tx INTEGER,PRIMARY KEY(day,app,kind)); CREATE TABLE IF NOT EXISTS state(key TEXT PRIMARY KEY,value TEXT); CREATE TABLE IF NOT EXISTS inventory(path TEXT PRIMARY KEY,fingerprint TEXT NOT NULL,detail TEXT NOT NULL,updated REAL NOT NULL);" arguments:@[]])
        @throw [NSException exceptionWithName:@"Database" reason:@"Could not initialize the log schema" userInfo:nil];
    NSDictionary *saved=[self query:@"SELECT value FROM state WHERE key='retention_counters'" arguments:@[]].firstObject;
    NSDictionary *counters=saved ? [NSJSONSerialization JSONObjectWithData:[saved[@"value"] dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil] : nil;
    _dropped=[counters[@"dropped"] unsignedLongLongValue]; _pruned=[counters[@"pruned"] unsignedLongLongValue]; _unreviewedPruned=[counters[@"unreviewed_pruned"] unsignedLongLongValue];
    _prunedStatistics=[counters[@"pruned_statistics"] unsignedLongLongValue];
    return self;
}
- (BOOL)execute:(NSString *)sql arguments:(NSArray *)arguments {
    if(_readOnly && ![@[@"BEGIN",@"BEGIN DEFERRED",@"COMMIT",@"ROLLBACK"] containsObject:sql]) return NO;
    if (!arguments.count) {
        _databaseResult=sqlite3_exec(_db, sql.UTF8String, NULL, NULL, NULL);
        return _databaseResult==SQLITE_OK;
    }
    sqlite3_stmt *s = NULL;
    _databaseResult=sqlite3_prepare_v2(_db,sql.UTF8String,-1,&s,NULL);
    if (_databaseResult!=SQLITE_OK) return NO;
    for (NSUInteger i=0;i<arguments.count;i++) {
        id v=arguments[i];
        if (v==NSNull.null) sqlite3_bind_null(s,(int)i+1);
        else if ([v isKindOfClass:NSNumber.class]) sqlite3_bind_double(s,(int)i+1,[v doubleValue]);
        else sqlite3_bind_text(s,(int)i+1,[v description].UTF8String,-1,SQLITE_TRANSIENT);
    }
    int result=sqlite3_step(s);
    sqlite3_finalize(s);
    _databaseResult=result==SQLITE_DONE?SQLITE_OK:result;
    return _databaseResult==SQLITE_OK;
}
- (NSArray *)query:(NSString *)sql arguments:(NSArray *)arguments {
    sqlite3_stmt *s=NULL; NSMutableArray *rows=[NSMutableArray new];
    _databaseResult=sqlite3_prepare_v2(_db,sql.UTF8String,-1,&s,NULL);
    if(_databaseResult!=SQLITE_OK) return rows;
    for(NSUInteger i=0;i<arguments.count;i++) {
        id v=arguments[i];
        if([v isKindOfClass:NSNumber.class]) sqlite3_bind_double(s,(int)i+1,[v doubleValue]);
        else sqlite3_bind_text(s,(int)i+1,[v description].UTF8String,-1,SQLITE_TRANSIENT);
    }
    int result;
    while((result=sqlite3_step(s))==SQLITE_ROW) {
        NSMutableDictionary *r=[NSMutableDictionary new];
        for(int i=0;i<sqlite3_column_count(s);i++) {
            NSString *k=@(sqlite3_column_name(s,i)); int type=sqlite3_column_type(s,i);
            if(type==SQLITE_INTEGER) r[k]=@(sqlite3_column_int64(s,i));
            else if(type==SQLITE_FLOAT) r[k]=@(sqlite3_column_double(s,i));
            else if(type==SQLITE_TEXT) r[k]=@((const char *)sqlite3_column_text(s,i));
            else r[k]=NSNull.null;
        }
        [rows addObject:r];
    }
    sqlite3_finalize(s);
    _databaseResult=result==SQLITE_DONE?SQLITE_OK:result;
    return _databaseResult==SQLITE_OK?rows:@[];
}
- (void)record:(NSString *)kind actor:(NSDictionary *)actor source:(NSString *)source detail:(NSDictionary *)detail priority:(NSInteger)priority {
    [self record:kind actor:actor source:source detail:detail priority:priority at:NSDate.date.timeIntervalSince1970];
}
- (void)record:(NSString *)kind actor:(NSDictionary *)actor source:(NSString *)source detail:(NSDictionary *)detail priority:(NSInteger)priority at:(NSTimeInterval)time {
    [self record:kind actor:actor source:source detail:detail priority:priority first:time last:time count:1];
}
- (void)record:(NSString *)kind actor:(NSDictionary *)actor source:(NSString *)source detail:(NSDictionary *)detail priority:(NSInteger)priority first:(NSTimeInterval)first last:(NSTimeInterval)time count:(long long)count {
    if(count<1)count=1;if(first>time)first=time;
    _received+=(uint64_t)count;
    NSString *app=[actor[@"app"] isKindOfClass:NSString.class]&&[actor[@"app"] length] ? actor[@"app"] : @"unknown", *encoded=AOJSON(cleanJSON(detail,0));
    NSString *actorPath=[actor[@"path"] isKindOfClass:NSString.class]?actor[@"path"]:@"";
    NSNumber *actorPID=[actor[@"pid"] isKindOfClass:NSNumber.class]?actor[@"pid"]:@0;
    if(app.length>1024)app=[app substringToIndex:1024];if(actorPath.length>4096)actorPath=[actorPath substringToIndex:4096];
    if([encoded lengthOfBytesUsingEncoding:NSUTF8StringEncoding]>8192) {
        NSData *original=[encoded dataUsingEncoding:NSUTF8StringEncoding];
        encoded=AOJSON(@{@"detail_truncated":@YES,@"original_bytes":@(original.length),@"original_sha256":AOHash(original),@"preview":[encoded substringToIndex:MIN((NSUInteger)2048,encoded.length)]});
    }
    // Aggregate only within this short flush window. Rows never change after
    // insertion, so a review checkpoint cannot skip a subsequently updated row.
    NSString *key=AOHash([AOJSON(@[AODay(time),kind,app,actorPID,actorPath,source,encoded]) dataUsingEncoding:NSUTF8StringEncoding]);
    NSMutableDictionary *r=_pending[key];
    if(r) {
        r[@"first"]=@(MIN(first,[r[@"first"] doubleValue]));
        r[@"last"]=@(MAX(time,[r[@"last"] doubleValue]));
        r[@"count"]=@([r[@"count"] longLongValue]+count);
        return;
    }
    if(_pending.count>=4096) { _dropped+=(uint64_t)count; return; }
    _pending[key]=[@{@"first":@(first),@"last":@(time),@"day":AODay(time),@"kind":kind,@"app":app,@"pid":actorPID,@"path":actorPath,@"source":source,@"detail":encoded,@"priority":@(priority),@"count":@(count)} mutableCopy];
}
- (void)setSensor:(NSString *)name status:(NSString *)status detail:(NSString *)detail {
    NSDictionary *previous=_health[name];
    _health[name]=@{@"status":status,@"detail":detail,@"checked_at":@(NSDate.date.timeIntervalSince1970)};
    if(![previous[@"status"] isEqual:status] || ![previous[@"detail"] isEqual:detail])
        [self record:@"sensor_status" actor:@{@"app":@"activity-observer"} source:name detail:@{@"status":status,@"detail":detail} priority:[status isEqual:@"active"] ? 1 : 3];
}
- (int)writeTransaction:(BOOL (^)(void))work {
    int result=SQLITE_ERROR;
    NSString *reason=nil;
    BOOL began=[self execute:@"BEGIN IMMEDIATE" arguments:@[]];
    @try {
        if(began && work() && [self execute:@"COMMIT" arguments:@[]]) {
            result=SQLITE_OK;
        } else if(_databaseResult!=SQLITE_OK) {
            result=_databaseResult;
            reason=@(sqlite3_errmsg(_db));
        }
    } @catch(NSException *error) {
        reason=error.reason;
    } @finally {
        if(result!=SQLITE_OK) {
            int extended=sqlite3_extended_errcode(_db),system=sqlite3_system_errno(_db);
            if(began && !sqlite3_get_autocommit(_db)) [self execute:@"ROLLBACK" arguments:@[]];
            _lastStorageError=@{@"status":@"degraded",@"detail":reason ?: @"Could not commit the log transaction",@"sqlite_code":@(result),@"sqlite_extended_code":@(extended),@"system_errno":@(system),@"checked_at":@(NSDate.date.timeIntervalSince1970)};
            _health[@"storage"]=_lastStorageError;
        }
    }
    return result;
}
- (BOOL)saveRetentionCounters:(uint64_t)pruned unreviewed:(uint64_t)unreviewed statistics:(uint64_t)statistics {
    NSDictionary *counters=@{@"dropped":@(_dropped),@"pruned":@(pruned),@"unreviewed_pruned":@(unreviewed),@"pruned_statistics":@(statistics)};
    return [self execute:@"INSERT INTO state(key,value) VALUES('retention_counters',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value WHERE value<>excluded.value" arguments:@[AOJSON(counters)]];
}
- (NSUInteger)pagesOverRetentionThreshold {
    NSNumber *pages=[self query:@"PRAGMA page_count" arguments:@[]].firstObject[@"page_count"];
    NSNumber *free=[self query:@"PRAGMA freelist_count" arguments:@[]].firstObject[@"freelist_count"];
    if(!pages || !free || pages.unsignedLongLongValue<free.unsignedLongLongValue) return 0;
    // The limit covers the whole directory. The database may use what remains
    // after headroom for the write-ahead log, vacuuming and archived files:
    // three quarters of a small budget, and at most 500 MB of a large one.
    uint64_t headroom=MIN(_maxBytes/4*3,(uint64_t)500000000);
    return (pages.unsignedLongLongValue-free.unsignedLongLongValue)*4096>_maxBytes-headroom?pages.unsignedIntegerValue:0;
}
- (BOOL)prune:(NSUInteger)count {
    __block uint64_t removed=0, unreviewed=0, statistics=0;
    __block int64_t boundaryID=_boundaryID;
    __block NSString *boundaryHash=_boundaryHash;
    int result=[self writeTransaction:^BOOL{
        NSDictionary *selection=[self query:@"SELECT COUNT(*) AS total, SUM(id>COALESCE((SELECT CAST(value AS INTEGER) FROM state WHERE key='review_checkpoint'),0)) AS unreviewed, MAX(id) AS last FROM (SELECT id FROM events ORDER BY id LIMIT ?)" arguments:@[@(count)]].firstObject;
        if(!selection) return NO;
        removed=[selection[@"total"] unsignedLongLongValue];
        if(removed) {
            unreviewed=[selection[@"unreviewed"] unsignedLongLongValue];
            NSNumber *last=selection[@"last"];
            if(_integrity) {
                boundaryID=last.longLongValue;
                id hash=[self query:@"SELECT chain_hash FROM events WHERE id=?" arguments:@[last]].firstObject[@"chain_hash"];
                if(![hash isKindOfClass:NSString.class] || [hash length]!=64 || boundaryID<=_boundaryID || boundaryID>_headID) return NO;
                boundaryHash=hash;
            }
            if(![self execute:@"DELETE FROM events WHERE id<=?" arguments:@[last]] || (uint64_t)sqlite3_changes(_db)!=removed) return NO;
        }
        if(removed<count && [self pagesOverRetentionThreshold]) {
            if(![self execute:@"DELETE FROM daily WHERE rowid IN (SELECT rowid FROM daily ORDER BY day,app,kind LIMIT ?)" arguments:@[@(count-removed)]]) return NO;
            statistics=(uint64_t)sqlite3_changes(_db);
        }
        if(_integrity && removed && ![self saveCheckpointAtHead:_headID hash:_headHash boundary:boundaryID hash:boundaryHash]) return NO;
        return [self saveRetentionCounters:_pruned+removed unreviewed:_unreviewedPruned+unreviewed statistics:_prunedStatistics+statistics];
    }];
    if(result!=SQLITE_OK) return NO;
    _boundaryID=boundaryID;
    _boundaryHash=boundaryHash;
    _pruned+=removed;
    _unreviewedPruned+=unreviewed;
    _prunedStatistics+=statistics;
    return removed || statistics;
}
- (void)flush {
    if(!_pending.count) return;
    NSArray *batch=[_pending.allValues sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *a,NSDictionary *b){
        NSComparisonResult order=[a[@"last"] compare:b[@"last"]];
        return order==NSOrderedSame?[a[@"first"] compare:b[@"first"]]:order;
    }];
    for(int attempt=0;attempt<3;attempt++) {
        __block NSString *headHash=_headHash;
        __block int64_t headID=_headID;
        int result=[self writeTransaction:^BOOL{
            for(NSDictionary *r in batch) {
                NSArray *args=@[r[@"first"],r[@"last"],r[@"day"],r[@"kind"],r[@"app"],r[@"pid"],r[@"path"],r[@"source"],r[@"detail"],r[@"priority"],r[@"count"]];
                if(![self execute:@"INSERT INTO events(first,last,day,kind,app,pid,path,source,detail,priority,count) VALUES(?,?,?,?,?,?,?,?,?,?,?)" arguments:args]) return NO;
                if(_integrity) {
                    NSDictionary *row=[self query:@"SELECT * FROM events WHERE id=?" arguments:@[@(sqlite3_last_insert_rowid(_db))]].firstObject;
                    if(!row) return NO;
                    NSString *hash=AOEventHash(row,headHash);
                    if(![self execute:@"UPDATE events SET chain_prev=?,chain_hash=? WHERE id=?" arguments:@[headHash,hash,row[@"id"]]]) return NO;
                    headHash=hash;
                    headID=[row[@"id"] longLongValue];
                }
                NSDictionary *detail=[NSJSONSerialization JSONObjectWithData:[r[@"detail"] dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
                long long count=[r[@"count"] longLongValue];
                if(![self execute:@"INSERT INTO daily(day,app,kind,count,rx,tx) VALUES(?,?,?,?,?,?) ON CONFLICT(day,app,kind) DO UPDATE SET count=count+excluded.count,rx=rx+excluded.rx,tx=tx+excluded.tx" arguments:@[r[@"day"],r[@"app"],r[@"kind"],r[@"count"],@([detail[@"rx_delta"] longLongValue]*count),@([detail[@"tx_delta"] longLongValue]*count)]]) return NO;
            }
            return !_integrity || [self saveCheckpointAtHead:headID hash:headHash boundary:_boundaryID hash:_boundaryHash];
        }];
        if(result==SQLITE_OK) {
            _headID=headID;
            _headHash=headHash;
            _written+=batch.count;
            [_pending removeAllObjects];
            if(_health[@"storage"] && ![_health[@"storage"][@"status"] isEqual:@"active"]) {
                [self record:@"storage_write_recovered" actor:@{@"app":@"activity-observer"} source:@"storage" detail:_health[@"storage"] priority:2];
                [self setSensor:@"storage" status:@"active" detail:@"Pending log writes committed after retry"];
            }
            return;
        }
        if(result==SQLITE_BUSY || result==SQLITE_LOCKED) return;
        if(result!=SQLITE_FULL || attempt==2 || ![self pagesOverRetentionThreshold] || ![self prune:MAX(2000,batch.count*2)]) break;
    }
    // Keep uncommitted observations for the next flush. The existing 4096
    // pattern bound limits memory; a temporary write error must not erase a batch.
}
- (void)maintain {
    [self flush];
    NSUInteger pages=[self pagesOverRetentionThreshold];
    if(pages) [self prune:MAX(2000,pages/4)];
    [self execute:@"PRAGMA incremental_vacuum(64)" arguments:@[]];
    [self writeStatus]; _lastMaintenance=NSDate.date.timeIntervalSince1970;
}
- (void)writeStatus {
    struct rusage ru={0}; getrusage(RUSAGE_SELF,&ru);
    double cpu=ru.ru_utime.tv_sec+ru.ru_utime.tv_usec/1e6+ru.ru_stime.tv_sec+ru.ru_stime.tv_usec/1e6;
    NSTimeInterval now=NSDate.date.timeIntervalSince1970;
    // Maintenance and heartbeat timers can fire milliseconds apart. Keep the
    // last meaningful sample instead of reporting a sub-millisecond CPU spike.
    if(!_previousSample) { _previousCPU=cpu; _previousSample=now; }
    else if(now-_previousSample>=5) {
        _lastCPUPercent=MAX(0,(cpu-_previousCPU)/(now-_previousSample)*100);
        _previousCPU=cpu; _previousSample=now;
    }
    double percent=_lastCPUPercent;
    mach_task_basic_info_data_t basic={0}; mach_msg_type_number_t n=MACH_TASK_BASIC_INFO_COUNT;
    task_info(mach_task_self(),MACH_TASK_BASIC_INFO,(task_info_t)&basic,&n);
    [self saveRetentionCounters:_pruned unreviewed:_unreviewedPruned statistics:_prunedStatistics];
    NSMutableDictionary *status=[@{@"schema":@1,@"pid":@(getpid()),@"started":@(_started),@"heartbeat":@(now),@"received":@(_received),@"written_rows":@(_written),@"dropped_events":@(_dropped),@"pruned_rows":@(_pruned),@"unreviewed_pruned_rows":@(_unreviewedPruned),@"pending_patterns":@(_pending.count),@"own_cpu_percent_one_core":@(percent),@"resident_bytes":@(basic.resident_size),@"data_bytes":@(AODirectoryBytes(_directory)),@"max_data_bytes":@(_maxBytes),@"sensors":_health} mutableCopy];
    status[@"retention_policy"]=@"capacity";
    status[@"pruned_statistics_rows"]=@(_prunedStatistics);
    if(_lastStorageError) status[@"last_storage_error"]=_lastStorageError;
    if(_integrity) {
        status[@"protection_mode"]=geteuid()==0?@"privileged_writer":@"development_signed_test";
        status[@"version"]=@AO_VERSION;
        status[@"boundary_id"]=@(_boundaryID);
        status[@"boundary_hash"]=_boundaryHash;
        status[@"integrity_signature"]=[_integrity sign:[status copy]];
    }
    NSString *path=[_directory stringByAppendingPathComponent:@"status.json"];
    int error=replaceStatusFile(path,[AOJSON(status) dataUsingEncoding:NSUTF8StringEncoding]);
    if(error)[self record:@"status_write_failed" actor:@{@"app":@"activity-observer"} source:@"storage"
                   detail:@{@"errno":@(error),@"error":@(strerror(error))} priority:3];
}
- (NSDictionary *)reportSinceCheckpoint:(BOOL)since day:(NSString *)day {
    int64_t checkpoint=since ? [[self query:@"SELECT CAST(value AS INTEGER) AS id FROM state WHERE key='review_checkpoint'" arguments:@[]].firstObject[@"id"] longLongValue] : 0;
    return [self reportAfterID:checkpoint day:day];
}
- (NSDictionary *)reportAfterID:(int64_t)checkpoint day:(NSString *)day {
    [self flush];
    int64_t through=[[self query:@"SELECT COALESCE(MAX(id),0) AS id FROM events" arguments:@[]].firstObject[@"id"] longLongValue];
    if(checkpoint<0||checkpoint>through)return @{@"error":@"review_anchor_outside_current_log",@"after_id":@(checkpoint),@"through_id":@(through)};
    NSString *where=day ? @"id>? AND id<=? AND day=?" : @"id>? AND id<=?";
    NSArray *a=day ? @[@(checkpoint),@(through),day] : @[@(checkpoint),@(through)];
    // Bound detailed examples before sorting/grouping. Complete review uses the
    // immutable event pages, so historical high-cardinality details need not be
    // materialized in memory by the privileged writer.
    NSArray *patterns=[self query:[NSString stringWithFormat:@"SELECT app,path,kind,source,detail,MIN(first) AS first,MAX(last) AS last,SUM(count) AS count,MAX(priority) AS priority FROM (SELECT * FROM events WHERE %@ ORDER BY id DESC LIMIT 256) GROUP BY app,path,kind,source,detail ORDER BY priority DESC,last DESC",where] arguments:a];
    NSArray *totals=[self query:[NSString stringWithFormat:@"SELECT app,kind,SUM(count) AS count,MIN(first) AS first,MAX(last) AS last FROM events WHERE %@ GROUP BY app,kind ORDER BY app,kind",where] arguments:a];
    NSNumber *rowCount=[self query:[NSString stringWithFormat:@"SELECT COUNT(*) AS n FROM events WHERE %@",where] arguments:a].firstObject[@"n"] ?: @0;
    NSData *statusData=[NSData dataWithContentsOfFile:[_directory stringByAppendingPathComponent:@"status.json"]];
    NSDictionary *status=statusData ? [NSJSONSerialization JSONObjectWithData:statusData options:0 error:nil] : @{};
    NSTimeInterval now=NSDate.date.timeIntervalSince1970;
    NSArray *history=[self query:@"SELECT app,kind,COUNT(*) AS active_days,SUM(count) AS event_count,SUM(rx) AS rx_bytes,SUM(tx) AS tx_bytes,MIN(day) AS first_day,MAX(day) AS last_day FROM daily WHERE day>=? AND day<? GROUP BY app,kind ORDER BY app,kind" arguments:@[AODay(now-14*86400),AODay(now)]];
    NSArray *today=[self query:@"SELECT * FROM daily WHERE day=? ORDER BY app,kind" arguments:@[day ?: AODay(now)]];
    return @{@"schema":@2,@"timezone":AOTimeZoneName(),@"generated_at":@(now),@"after_id":@(checkpoint),@"through_id":@(through),@"day":day ?: @"all_unreviewed",@"status":status ?: @{},@"all_app_activity_totals":totals,@"daily_statistics":today,@"previous_14_days":history,@"patterns":patterns,@"pattern_count":@(patterns.count),@"row_count":rowCount,@"pattern_scope":rowCount.longLongValue>256?@"recent_256_rows":@"complete_interval",@"patterns_truncated":@(rowCount.longLongValue>256),@"pagination":@"events --after ID --through ID --limit 500",@"interpretation":@"Patterns are bounded examples; page all immutable events for complete review. Activity observations are not malware verdicts. Check sensor health, dropped/pruned counters and coverage."};
}
- (BOOL)checkpoint:(int64_t)through {
    if(_readOnly) return NO;
    int64_t max=[[self query:@"SELECT COALESCE(MAX(id),0) AS id FROM events" arguments:@[]].firstObject[@"id"] longLongValue];
    int64_t old=[[self query:@"SELECT CAST(value AS INTEGER) AS id FROM state WHERE key='review_checkpoint'" arguments:@[]].firstObject[@"id"] longLongValue];
    if(through<old || through>max) return NO;
    return [self execute:@"INSERT INTO state(key,value) VALUES('review_checkpoint',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value" arguments:@[@(through)]];
}
- (BOOL)saveCheckpointAtHead:(int64_t)headID hash:(NSString *)headHash boundary:(int64_t)boundaryID hash:(NSString *)boundaryHash {
    if(!_integrity) return YES;
    NSDictionary *payload=@{@"schema":@1,@"head_id":@(headID),@"head_hash":headHash,@"boundary_id":@(boundaryID),@"boundary_hash":boundaryHash,@"protected_since":@(_sealedStarted),@"checkpoint_at":@(NSDate.date.timeIntervalSince1970),@"key_fingerprint":_integrity.fingerprint};
    return [self execute:@"INSERT INTO state(key,value) VALUES('integrity_checkpoint',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value" arguments:@[AOJSON([_integrity sign:payload])]];
}
- (void)enableIntegrity:(AOIntegrity *)integrity {
    _integrity=integrity;
    NSArray *columns=[self query:@"PRAGMA table_info(events)" arguments:@[]]; BOOL found=NO;
    for(NSDictionary *column in columns) if([column[@"name"] isEqual:@"chain_hash"]) found=YES;
    if(!found && [self writeTransaction:^BOOL{
        return [self execute:@"ALTER TABLE events ADD COLUMN chain_prev TEXT" arguments:@[]] &&
            [self execute:@"ALTER TABLE events ADD COLUMN chain_hash TEXT" arguments:@[]];
    }]!=SQLITE_OK) @throw [NSException exceptionWithName:@"Integrity" reason:@"Could not initialize event hashes" userInfo:nil];
    NSDictionary *saved=[self query:@"SELECT value FROM state WHERE key='integrity_checkpoint'" arguments:@[]].firstObject;
    if(saved) {
        NSDictionary *envelope=[NSJSONSerialization JSONObjectWithData:[saved[@"value"] dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
        NSDictionary *payload=envelope[@"payload"];
        NSString *error=nil;
        if(![AOIntegrity verify:envelope publicFile:AOPublicKeyFile(_directory) expectedFingerprint:integrity.fingerprint error:&error]) @throw [NSException exceptionWithName:@"Integrity" reason:error userInfo:nil];
        _headID=[payload[@"head_id"] longLongValue];_headHash=payload[@"head_hash"];
        _boundaryID=[payload[@"boundary_id"] longLongValue];_boundaryHash=payload[@"boundary_hash"];
        _sealedStarted=[payload[@"protected_since"] doubleValue];
        NSDictionary *verification=[self verifyIntegrity:integrity.fingerprint];
        if(![verification[@"valid"] boolValue]) @throw [NSException exceptionWithName:@"Integrity" reason:AOJSON(verification) userInfo:nil];
        return;
    }
    if([self query:@"SELECT id FROM events WHERE chain_hash IS NOT NULL LIMIT 1" arguments:@[]].count) @throw [NSException exceptionWithName:@"Integrity" reason:@"Signed rows exist but their checkpoint is missing" userInfo:nil];
    _sealedStarted=NSDate.date.timeIntervalSince1970; _headID=0;_boundaryID=0;
    _headHash=AOHash([[NSString stringWithFormat:@"ActivityObserver-genesis-v1|%@|%@",integrity.fingerprint,NSUUID.UUID.UUIDString] dataUsingEncoding:NSUTF8StringEncoding]);_boundaryHash=_headHash;
    __block NSString *headHash=_headHash;
    __block int64_t headID=0;
    int result=[self writeTransaction:^BOOL{
        while(YES) {@autoreleasepool{
            NSArray *rows=[self query:@"SELECT * FROM events WHERE id>? ORDER BY id LIMIT 256" arguments:@[@(headID)]];
            if(_databaseResult!=SQLITE_OK) return NO;
            if(!rows.count) break;
            for(NSDictionary *row in rows) {
                NSString *hash=AOEventHash(row,headHash);
                if(![self execute:@"UPDATE events SET chain_prev=?,chain_hash=? WHERE id=?" arguments:@[headHash,hash,row[@"id"]]]) return NO;
                headHash=hash;
                headID=[row[@"id"] longLongValue];
            }
        }}
        return [self saveCheckpointAtHead:headID hash:headHash boundary:0 hash:_boundaryHash];
    }];
    if(result!=SQLITE_OK) @throw [NSException exceptionWithName:@"Integrity" reason:@"Could not seal historical snapshot" userInfo:nil];
    _headID=headID;
    _headHash=headHash;
}
- (NSDictionary *)signedCheckpoint {
    NSString *value=[self query:@"SELECT value FROM state WHERE key='integrity_checkpoint'" arguments:@[]].firstObject[@"value"];
    if(!value) return @{@"error":@"integrity_checkpoint_unavailable"};
    NSDictionary *envelope=[NSJSONSerialization JSONObjectWithData:[value dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
    return envelope ?: @{@"error":@"invalid_integrity_checkpoint"};
}
- (NSDictionary *)verifyIntegrity:(NSString *)expectedFingerprint {
    return [self verifyIntegrity:expectedFingerprint live:NO];
}
- (NSDictionary *)verifyIntegrity:(NSString *)expectedFingerprint live:(BOOL)live {
    return [self verifyIntegrity:expectedFingerprint live:live readQueue:nil];
}
- (NSDictionary *)verifyIntegrity:(NSString *)expectedFingerprint live:(BOOL)live readQueue:(dispatch_queue_t)queue {
    if(queue && !live) return @{@"error":@"invalid_verification_mode"};
    // SQL reads share the writer's serial queue and connection. Hashing runs
    // off that queue, so collection can commit between bounded page reads.
    void (^read)(dispatch_block_t)=^(dispatch_block_t work){
        if(queue) dispatch_sync(queue,work); else work();
    };
    __block NSDictionary *envelope, *last, *startError;
    __block BOOL reading=NO;
    @try {
        read(^{
            if(![self execute:@"BEGIN DEFERRED" arguments:@[]]) {
                startError=@{@"error":@"verification_snapshot_unavailable"};return;
            }
            reading=YES;
            envelope=[self signedCheckpoint];
            last=[self query:@"SELECT id FROM events ORDER BY id DESC LIMIT 1" arguments:@[]].firstObject;
            if(self->_databaseResult!=SQLITE_OK) startError=@{@"error":@"verification_read_failed"};
            if(live) {
                if([self execute:@"ROLLBACK" arguments:@[]]) reading=NO;
                else startError=@{@"error":@"verification_snapshot_unavailable"};
            }
        });
        if(startError) return startError;
        if(envelope[@"error"]) return @{@"valid":@NO,@"reason":@"No readable signed checkpoint"};
        NSString *error=nil;
        if(![AOIntegrity verify:envelope publicFile:AOPublicKeyFile(_directory) expectedFingerprint:expectedFingerprint error:&error]) return @{@"valid":@NO,@"reason":error ?: @"Invalid checkpoint"};
        NSDictionary *checkpoint=envelope[@"payload"];
        NSNumber *lastID=last[@"id"] ?: checkpoint[@"boundary_id"];
        if(![lastID isEqual:checkpoint[@"head_id"]]) return @{@"valid":@NO,@"reason":@"Log head differs from signed checkpoint"};
        NSString *previous=checkpoint[@"boundary_hash"];
        int64_t cursor=[checkpoint[@"boundary_id"] longLongValue];
        int64_t through=[checkpoint[@"head_id"] longLongValue];
        NSUInteger verified=0;
        NSTimeInterval deadline=NSProcessInfo.processInfo.systemUptime+110;
        while(cursor<through) {@autoreleasepool{
            if(live && NSProcessInfo.processInfo.systemUptime>=deadline) return @{@"error":@"verification_time_limit"};
            __block NSArray *rows;
            __block BOOL failed;
            read(^{
                rows=[self query:@"SELECT * FROM events WHERE id>? AND id<=? ORDER BY id LIMIT 256" arguments:@[@(cursor),@(through)]];
                failed=self->_databaseResult!=SQLITE_OK;
            });
            if(failed) return @{@"error":@"verification_read_failed"};
            if(live && (!rows.count || ![rows.firstObject[@"chain_prev"] isEqual:previous])) {
                __block NSDictionary *current;
                read(^{ current=[self signedCheckpoint]; });
                if([AOIntegrity verify:current publicFile:AOPublicKeyFile(_directory) expectedFingerprint:expectedFingerprint error:nil] &&
                   [current[@"payload"][@"boundary_id"] longLongValue]>cursor) {
                    return @{@"error":@"verification_range_pruned"};
                }
            }
            if(!rows.count) break;
            for(NSDictionary *event in rows) {
                NSString *computed=AOEventHash(event,previous);
                if(![event[@"chain_prev"] isEqual:previous]||![event[@"chain_hash"] isEqual:computed]) return @{@"valid":@NO,@"reason":@"Event hash chain mismatch",@"event_id":event[@"id"]};
                previous=computed;cursor=[event[@"id"] longLongValue];verified++;
            }
        }}
        if(cursor!=through||![previous isEqual:checkpoint[@"head_hash"]]) return @{@"valid":@NO,@"reason":@"Log head differs from signed checkpoint"};
        return @{@"valid":@YES,@"verified_rows":@(verified),@"checkpoint":envelope};
    } @finally {
        if(reading) read(^{ [self execute:@"ROLLBACK" arguments:@[]]; });
    }
}
- (NSDictionary *)activityQuery:(NSDictionary *)request {
    NSString *mode=request[@"mode"],*start=request[@"start"],*end=request[@"end"];
    for(id value in @[mode ?: NSNull.null,start ?: NSNull.null,end ?: NSNull.null])
        if(![value isKindOfClass:NSString.class]) return @{@"error":@"invalid_query"};
    if(![@[@"catalog",@"program"] containsObject:mode] ||
       ![start rangeOfString:@"^[0-9]{4}-[0-9]{2}-[0-9]{2}$" options:NSRegularExpressionSearch].length ||
       ![end rangeOfString:@"^[0-9]{4}-[0-9]{2}-[0-9]{2}$" options:NSRegularExpressionSearch].length || [start compare:end]==NSOrderedDescending)
        return @{@"error":@"invalid_query"};
    for(NSString *key in @[@"after",@"through",@"cursor"])
        if(![request[key] isKindOfClass:NSNumber.class] || [request[key] doubleValue]!=[request[key] longLongValue]) return @{@"error":@"invalid_query"};
    int64_t after=[request[@"after"] longLongValue],through=[request[@"through"] longLongValue],cursor=[request[@"cursor"] longLongValue];
    if(after<0 || after>through || through>_headID || cursor<after || cursor>through) return @{@"error":@"invalid_query_range"};
    if(after<_boundaryID) return @{@"error":@"query_range_pruned"};
    NSMutableDictionary *query=[@{@"mode":mode,@"start":start,@"end":end,@"after":@(after),@"through":@(through),@"cursor":@(cursor)} mutableCopy];
    NSMutableArray *arguments=[NSMutableArray arrayWithArray:@[@(cursor),@(through),start,end]];
    NSMutableString *where=[@"id>? AND id<=? AND day>=? AND day<=?" mutableCopy];
    if([mode isEqual:@"program"]) {
        NSArray *actors=request[@"actors"];
        if(![actors isKindOfClass:NSArray.class] || !actors.count || actors.count>512) return @{@"error":@"invalid_query_actors"};
        NSMutableArray *clauses=[NSMutableArray new],*validated=[NSMutableArray new];
        for(id actor in actors) {
            if(![actor isKindOfClass:NSDictionary.class] || ![actor[@"app"] isKindOfClass:NSString.class] || ![actor[@"path"] isKindOfClass:NSString.class] ||
               [actor[@"app"] length]>1024 || [actor[@"path"] length]>4096 || ![@[@"network",@"other"] containsObject:actor[@"kind"]]) return @{@"error":@"invalid_query_actors"};
            [validated addObject:@{@"app":actor[@"app"],@"path":actor[@"path"],@"kind":actor[@"kind"]}];
            [clauses addObject:@"(app=? AND COALESCE(path,'')=? AND (kind GLOB 'network_*')=?)"];
            [arguments addObjectsFromArray:@[actor[@"app"],actor[@"path"],@([actor[@"kind"] isEqual:@"network"])]];
        }
        query[@"actors"]=validated;
        [where appendFormat:@" AND (%@)",[clauses componentsJoinedByString:@" OR "]];
    }
    NSString *sql=[mode isEqual:@"catalog"] ?
        [NSString stringWithFormat:@"SELECT day,app,COALESCE(path,'') AS path,CASE WHEN kind GLOB 'network_*' THEN 'network' ELSE 'other' END AS kind,COUNT(*) AS records,MIN(first) AS first,MAX(last) AS last FROM events WHERE %@ GROUP BY day,app,path,(kind GLOB 'network_*') ORDER BY MIN(id) LIMIT 4097",where] :
        [NSString stringWithFormat:@"SELECT * FROM events WHERE %@ ORDER BY id LIMIT 500",where];
    NSArray *rows=[self query:sql arguments:arguments];
    if(_databaseResult!=SQLITE_OK) return @{@"error":@"query_read_failed"};
    if([mode isEqual:@"catalog"] && rows.count>4096) return @{@"error":@"query_catalog_limit"};
    if(!_integrity) return @{@"error":@"query_signing_unavailable"};
    return [_integrity sign:@{@"schema":@1,@"query":query,@"rows":rows,@"boundary_id":@(_boundaryID),
        @"next_after":[mode isEqual:@"program"]?(rows.lastObject[@"id"] ?: @(cursor)):@(through),
        @"has_more":@([mode isEqual:@"program"] && rows.count==500 && [rows.lastObject[@"id"] longLongValue]<through)}];
}
- (NSDictionary *)signedSnapshot {
    if(!_integrity) return @{@"error":@"No signing authority"};
    [self flush];
    NSString *dailyDigest=[self digestQuery:@"SELECT * FROM daily ORDER BY day,app,kind"];
    NSString *inventoryDigest=[self digestQuery:@"SELECT * FROM inventory ORDER BY path"];
    if(!dailyDigest || !inventoryDigest) return @{@"error":@"snapshot_digest_unavailable"};
    return [_integrity sign:@{@"schema":@1,@"created_at":@(NSDate.date.timeIntervalSince1970),@"head_id":@(_headID),@"head_hash":_headHash,@"daily_statistics_hash":dailyDigest,@"inventory_hash":inventoryDigest}];
}
- (NSString *)digestQuery:(NSString *)sql {
    CC_SHA256_CTX context;CC_SHA256_Init(&context);sqlite3_stmt *statement=NULL;
    if(sqlite3_prepare_v2(_db,sql.UTF8String,-1,&statement,NULL)!=SQLITE_OK)return nil;
    int result;
    while((result=sqlite3_step(statement))==SQLITE_ROW){@autoreleasepool{
        NSMutableDictionary *row=[NSMutableDictionary new];
        for(int i=0;i<sqlite3_column_count(statement);i++){
            NSString *key=@(sqlite3_column_name(statement,i));int type=sqlite3_column_type(statement,i);
            if(type==SQLITE_INTEGER)row[key]=@(sqlite3_column_int64(statement,i));
            else if(type==SQLITE_FLOAT)row[key]=@(sqlite3_column_double(statement,i));
            else if(type==SQLITE_TEXT)row[key]=@((const char *)sqlite3_column_text(statement,i));
            else row[key]=NSNull.null;
        }
        NSData *bytes=[[AOJSON(row) stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding];CC_SHA256_Update(&context,bytes.bytes,(CC_LONG)bytes.length);
    }}
    sqlite3_finalize(statement);
    if(result!=SQLITE_DONE) return nil;
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];CC_SHA256_Final(digest,&context);
    NSMutableString *hex=[NSMutableString new];for(unsigned i=0;i<sizeof(digest);i++)[hex appendFormat:@"%02x",digest[i]];return hex;
}
- (void)close { if(_db) { [self flush]; sqlite3_close(_db); _db=NULL; } }
@end
