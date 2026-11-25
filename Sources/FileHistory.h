#import <Foundation/Foundation.h>
#import <CoreServices/CoreServices.h>

// The sink receives path hints from the journal, never inferred file operations.
// Called off the live sensor queues. Only one caller should run at a time.
void AOReadFileHistory(FSEventStreamEventId after, FSEventStreamEventId through,
                       NSArray<NSString *> *roots, NSSet<NSString *> *known,
                       void (^emit)(NSString *kind, NSDictionary *detail));
