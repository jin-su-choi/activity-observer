#import <AppKit/AppKit.h>

// Presentation only: reading an icon does not launch or trust the application.
int main(void) {
  @autoreleasepool {
    NSArray *request = [NSJSONSerialization JSONObjectWithData:[[NSFileHandle fileHandleWithStandardInput] readDataToEndOfFile] options:0 error:nil];
    if (![request isKindOfClass:[NSArray class]]) return 1;
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    for (NSDictionary *item in request) {
      for (NSString *path in item[@"paths"]) {
        if (![path.pathExtension isEqualToString:@"app"]) continue;
        NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:[path stringByAppendingPathComponent:@"Contents/Info.plist"]];
        if (!info[@"CFBundleIconFile"] && !info[@"CFBundleIconName"] && !info[@"CFBundleIcons"]) continue;
        NSImage *image = [[NSWorkspace sharedWorkspace] iconForFile:path];
        NSBitmapImageRep *rep = [[NSBitmapImageRep alloc] initWithBitmapDataPlanes:NULL pixelsWide:64 pixelsHigh:64 bitsPerSample:8 samplesPerPixel:4 hasAlpha:YES isPlanar:NO colorSpaceName:NSCalibratedRGBColorSpace bytesPerRow:0 bitsPerPixel:0];
        [NSGraphicsContext saveGraphicsState];
        [NSGraphicsContext setCurrentContext:[NSGraphicsContext graphicsContextWithBitmapImageRep:rep]];
        [image drawInRect:NSMakeRect(0, 0, 64, 64) fromRect:NSZeroRect operation:NSCompositingOperationCopy fraction:1];
        [NSGraphicsContext restoreGraphicsState];
        NSData *png = [rep representationUsingType:NSBitmapImageFileTypePNG properties:@{}];
        if (png.length > 0 && png.length < 30000) {
          result[item[@"id"]] = [@"data:image/png;base64," stringByAppendingString:[png base64EncodedStringWithOptions:0]];
          break;
        }
      }
    }
    NSData *output = [NSJSONSerialization dataWithJSONObject:result options:0 error:nil];
    [[NSFileHandle fileHandleWithStandardOutput] writeData:output];
    return 0;
  }
}
