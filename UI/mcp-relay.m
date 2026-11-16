#import <Foundation/Foundation.h>
#import <curl/curl.h>
#import <sys/stat.h>

static size_t collect(char *bytes, size_t size, size_t count, void *context) {
    NSMutableData *data=(__bridge NSMutableData *)context;
    size_t length=size*count;
    if(data.length+length>8*1024*1024) return 0;
    [data appendBytes:bytes length:length];
    return length;
}

// Desktop clients that only launch stdio use this small transport adapter.
// All tools, log reads, validation and caches belong to the shared backend.
int main(void) {@autoreleasepool {
    NSString *path=[NSHomeDirectory() stringByAppendingPathComponent:@"Library/Application Support/ActivityObserver UI/UI/connection.json"];
    struct stat info;
    if(lstat(path.fileSystemRepresentation,&info)||!S_ISREG(info.st_mode)||info.st_uid!=getuid()||(info.st_mode&0077)||info.st_size>2048) return 77;
    NSDictionary *config=[NSJSONSerialization JSONObjectWithData:[NSData dataWithContentsOfFile:path] options:0 error:nil];
    NSString *url=config[@"url"],*token=config[@"token"];
    if(![url isEqual:@"http://127.0.0.1:47652/mcp"]||![token isKindOfClass:NSString.class]||token.length!=64||
       [token rangeOfCharacterFromSet:[[NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdef"] invertedSet]].location!=NSNotFound) return 77;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    CURL *curl=curl_easy_init();
    if(!curl) return 1;
    char *line=NULL; size_t capacity=0; ssize_t length;
    NSString *version=@"2025-11-25";
    while((length=getline(&line,&capacity,stdin))>=0) {@autoreleasepool {
        if(length>262144) break;
        NSData *input=[NSData dataWithBytes:line length:(NSUInteger)length];
        NSDictionary *message=[NSJSONSerialization JSONObjectWithData:input options:0 error:nil];
        if(![message isKindOfClass:NSDictionary.class]) break;
        NSDictionary *params=[message[@"params"] isKindOfClass:NSDictionary.class]?message[@"params"]:@{};
        NSString *provided=params[@"protocolVersion"];
        if([message[@"method"] isEqual:@"initialize"]&&[provided isKindOfClass:NSString.class]&&
           [provided rangeOfString:@"^[0-9]{4}-[0-9]{2}-[0-9]{2}$" options:NSRegularExpressionSearch].location!=NSNotFound) version=provided;
        NSMutableData *output=[NSMutableData new];
        struct curl_slist *headers=NULL;
        for(NSString *header in @[@"Content-Type: application/json",@"Accept: application/json, text/event-stream",
            [@"Authorization: Bearer " stringByAppendingString:token], [@"MCP-Protocol-Version: " stringByAppendingString:version]]) {
            headers=curl_slist_append(headers,header.UTF8String);
        }
        curl_easy_setopt(curl,CURLOPT_URL,url.UTF8String);
        curl_easy_setopt(curl,CURLOPT_PROXY,"");
        curl_easy_setopt(curl,CURLOPT_FOLLOWLOCATION,0L);
        curl_easy_setopt(curl,CURLOPT_CONNECTTIMEOUT,5L);
        curl_easy_setopt(curl,CURLOPT_TIMEOUT,150L);
        curl_easy_setopt(curl,CURLOPT_HTTPHEADER,headers);
        curl_easy_setopt(curl,CURLOPT_POSTFIELDS,line);
        curl_easy_setopt(curl,CURLOPT_POSTFIELDSIZE,(long)length);
        curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,collect);
        curl_easy_setopt(curl,CURLOPT_WRITEDATA,(__bridge void *)output);
        CURLcode result=curl_easy_perform(curl);
        long status=0;curl_easy_getinfo(curl,CURLINFO_RESPONSE_CODE,&status);
        curl_slist_free_all(headers);
        if(result!=CURLE_OK || status==401 || status==403 || status>=500) { fprintf(stderr,"Local Activity Observer connection failed (%ld).\n",status); break; }
        if(!message[@"id"]) continue;
        NSString *text=[[NSString alloc] initWithData:output encoding:NSUTF8StringEncoding];
        NSArray *lines=[text hasPrefix:@"{"]?@[text]:[text componentsSeparatedByString:@"\n"];
        for(NSString *part in lines) {
            NSString *json=[part hasPrefix:@"data: "]?[part substringFromIndex:6]:part;
            NSDictionary *reply=[NSJSONSerialization JSONObjectWithData:[json dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
            if(![reply isKindOfClass:NSDictionary.class] || !reply[@"jsonrpc"]) continue;
            NSDictionary *response=[reply[@"result"] isKindOfClass:NSDictionary.class]?reply[@"result"]:@{};
            NSString *negotiated=response[@"protocolVersion"];
            if([negotiated isKindOfClass:NSString.class]) version=negotiated;
            puts(json.UTF8String);
        }
        fflush(stdout);
    }}
    free(line);curl_easy_cleanup(curl);curl_global_cleanup();
    return feof(stdin)?0:1;
}}
