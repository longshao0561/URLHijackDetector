// URLHijackDetector.m
// iOS URL Hijack Dylib
#import <Foundation/Foundation.h>
#import <objc/runtime.h>

#pragma mark - 配置区

static NSSet<NSString *> *getTargetURLs(void) {
    return [NSSet setWithArray:@[
        @"http://api1.7ccccccc.com/v1/card/login",
        @"http://api1.7ccccccc.com/v1/card/heartbeat",
        @"http://api1.7ccccccc.com/v1/card/logout",
        @"http://api2.7ccccccc.com/v1/card/login",
        @"http://api2.7ccccccc.com/v1/card/heartbeat",
        @"http://api2.7ccccccc.com/v1/card/logout",
        @"http://api3.7ccccccc.com/v1/card/login",
        @"http://api3.7ccccccc.com/v1/card/heartbeat",
        @"http://api3.7ccccccc.com/v1/card/logout"
    ]];
}

static NSString *getNewDomain(void) {
    return @"api123.hezijun.top";
}

#pragma mark - URL 匹配与替换

static NSString* replaceURL(NSString *originalURLString) {
    if ([getTargetURLs() containsObject:originalURLString]) {
        NSURL *url = [NSURL URLWithString:originalURLString];
        NSString *path = url.path;
        NSString *scheme = url.scheme ?: @"http";
        return [NSString stringWithFormat:@"%@://%@%@", scheme, getNewDomain(), path];
    }
    return originalURLString;
}

#pragma mark - NSURLSession Hook

@interface NSURLSession (Hijack)
@end

@implementation NSURLSession (Hijack)

+ (void)load {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        Class class = [NSURLSession class];
        
        SEL originalSelector = @selector(dataTaskWithRequest:completionHandler:);
        SEL swizzledSelector = @selector(hijacked_dataTaskWithRequest:completionHandler:);
        
        Method originalMethod = class_getInstanceMethod(class, originalSelector);
        
        if (!originalMethod) return;
        
        __block id replacementBlock = ^(id self, NSURLRequest *request, void (^completionHandler)(NSData*, NSURLResponse*, NSError*)) {
            return [self hijacked_dataTaskWithRequest:request completionHandler:completionHandler];
        };
        
        class_addMethod(class, swizzledSelector, imp_implementationWithBlock(replacementBlock), "@@:@?");
        
        Method swizzledMethod = class_getInstanceMethod(class, swizzledSelector);
        
        if (originalMethod && swizzledMethod) {
            method_exchangeImplementations(originalMethod, swizzledMethod);
        }
    });
}

- (NSURLSessionDataTask *)hijacked_dataTaskWithRequest:(NSURLRequest *)request 
                                      completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler {
    
    NSString *newURLString = replaceURL(request.URL.absoluteString);
    
    if (![newURLString isEqualToString:request.URL.absoluteString]) {
        NSMutableURLRequest *mutableRequest = [request mutableCopy];
        [mutableRequest setURL:[NSURL URLWithString:newURLString]];
        return [self hijacked_dataTaskWithRequest:mutableRequest completionHandler:completionHandler];
    }
    
    return [self hijacked_dataTaskWithRequest:request completionHandler:completionHandler];
}

@end

__attribute__((constructor))
static void initialize() {
    // 静默加载
}
