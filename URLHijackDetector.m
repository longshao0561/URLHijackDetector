// URLHijackDetector.m
// iOS URL Hijack Dylib - 域名匹配版
#import <Foundation/Foundation.h>
#import <objc/runtime.h>

#pragma mark - 配置区

// 需要劫持的目标域名
static NSSet<NSString *> *getTargetDomains(void) {
    return [NSSet setWithArray:@[
        @"api1.7ccccccc.com",
        @"api2.7ccccccc.com",
        @"api3.7ccccccc.com"
    ]];
}

// 劫持后重定向的新域名
static NSString *getNewDomain(void) {
    return @"api123.hezijun.top";
}

#pragma mark - URL 匹配与替换

static NSString* replaceURL(NSString *originalURLString) {
    NSURL *url = [NSURL URLWithString:originalURLString];
    if (!url) return originalURLString;
    
    NSString *host = url.host;
    if (!host) return originalURLString;
    
    // 精确匹配域名
    if ([getTargetDomains() containsObject:host]) {
        // 替换域名，保留完整路径、参数、锚点
        NSString *newURLString = [originalURLString stringByReplacingOccurrencesOfString:host 
                                                                               withString:getNewDomain()];
        return newURLString;
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
