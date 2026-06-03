// URLHijackDetector.m
// iOS URL Hijack Dylib - 域名仅改appKey，IP做重定向+改appKey
#import <Foundation/Foundation.h>
#import <objc/runtime.h>

#pragma mark - 配置区

// 需要处理的目标域名/IP
static NSSet<NSString *> *getTargetDomains(void) {
    return [NSSet setWithArray:@[
        @"api1.7ccccccc.com",
        @"api2.7ccccccc.com", 
        @"api3.7ccccccc.com",
        @"45.205.27.82:8080"   // IP需要重定向
    ]];
}

// 需要重定向的IP列表（仅IP需要重定向到新域名）
static NSSet<NSString *> *getRedirectIPs(void) {
    return [NSSet setWithArray:@[
        @"45.205.27.82:8080"
    ]];
}

// 劫持后重定向的新域名（仅对IP生效）
static NSString *getNewDomain(void) {
    return @"api123.hezijun.top";
}

#pragma mark - 请求参数修改

static NSData* modifyRequestBody(NSData *originalBody, NSString *originalURL) {
    if (!originalBody) return originalBody;
    
    NSString *bodyString = [[NSString alloc] initWithData:originalBody encoding:NSUTF8StringEncoding];
    if (!bodyString) return originalBody;
    
    // 原 appKey 值
    NSString *oldAppKey = @"LWtAvVixXX39mGYL2w";
    // 新 appKey 值
    NSString *newAppKey = @"QLObIPwnDOVts3mzw9";
    
    // 在 body 中替换 appKey
    NSString *newBodyString = [bodyString stringByReplacingOccurrencesOfString:oldAppKey 
                                                                     withString:newAppKey];
    
    if ([newBodyString isEqualToString:bodyString]) {
        return originalBody; // 没有变化，返回原数据
    }
    
    NSLog(@"[Hijack] AppKey replaced in request body for: %@", originalURL);
    return [newBodyString dataUsingEncoding:NSUTF8StringEncoding];
}

#pragma mark - URL 匹配与替换

static NSString* replaceURLIfNeeded(NSString *originalURLString) {
    NSURL *url = [NSURL URLWithString:originalURLString];
    if (!url) return originalURLString;
    
    NSString *host = url.host;
    if (!host) return originalURLString;
    
    // 处理带端口的 host
    NSString *hostWithPort = nil;
    if (url.port) {
        hostWithPort = [NSString stringWithFormat:@"%@:%@", host, url.port];
    }
    
    // 检查是否需要重定向（仅IP需要重定向）
    BOOL needsRedirect = NO;
    if (hostWithPort && [getRedirectIPs() containsObject:hostWithPort]) {
        needsRedirect = YES;
    } else if ([getRedirectIPs() containsObject:host]) {
        needsRedirect = YES;
    }
    
    if (needsRedirect) {
        // 替换为新域名，保留原路径
        NSString *newURLString = originalURLString;
        
        // 替换 host（IP 地址）
        newURLString = [newURLString stringByReplacingOccurrencesOfString:host 
                                                               withString:getNewDomain()];
        // 去掉端口（新域名默认 80/443）
        if (url.port) {
            NSString *oldPortStr = [NSString stringWithFormat:@":%d", [url.port intValue]];
            newURLString = [newURLString stringByReplacingOccurrencesOfString:oldPortStr 
                                                                   withString:@""];
        }
        
        NSLog(@"[Hijack] URL redirected: %@ -> %@", originalURLString, newURLString);
        return newURLString;
    }
    
    // 域名不做重定向，直接返回原 URL
    return originalURLString;
}

// 检查请求是否需要处理（域名或IP是否在目标列表中）
static BOOL isTargetRequest(NSString *urlString) {
    NSURL *url = [NSURL URLWithString:urlString];
    if (!url) return NO;
    
    NSString *host = url.host;
    if (!host) return NO;
    
    // 检查域名（不带端口）
    if ([getTargetDomains() containsObject:host]) {
        return YES;
    }
    
    // 检查 IP:端口
    if (url.port) {
        NSString *hostWithPort = [NSString stringWithFormat:@"%@:%@", host, url.port];
        if ([getTargetDomains() containsObject:hostWithPort]) {
            return YES;
        }
    }
    
    return NO;
}

#pragma mark - NSURLSession Hook

@interface NSURLSession (Hijack)
@end

@implementation NSURLSession (Hijack)

+ (void)load {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        Class class = [NSURLSession class];
        
        // Hook dataTaskWithRequest:completionHandler:
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
    
    NSString *originalURLString = request.URL.absoluteString;
    NSMutableURLRequest *mutableRequest = [request mutableCopy];
    BOOL modified = NO;
    
    // 检查是否是目标请求
    if (isTargetRequest(originalURLString)) {
        
        // 1. 处理 URL 重定向（仅IP需要）
        NSString *newURLString = replaceURLIfNeeded(originalURLString);
        if (![newURLString isEqualToString:originalURLString]) {
            [mutableRequest setURL:[NSURL URLWithString:newURLString]];
            modified = YES;
        }
        
        // 2. 修改请求体中的 appKey（所有目标请求都需要）
        if ([request.HTTPMethod isEqualToString:@"POST"] && request.HTTPBody) {
            NSData *newBody = modifyRequestBody(request.HTTPBody, originalURLString);
            if (newBody != request.HTTPBody) {
                [mutableRequest setHTTPBody:newBody];
                // 更新 Content-Length header
                [mutableRequest setValue:[NSString stringWithFormat:@"%lu", (unsigned long)newBody.length] 
                      forHTTPHeaderField:@"Content-Length"];
                modified = YES;
            }
        }
    }
    
    // 如果没有任何修改，直接调用原方法
    if (!modified) {
        return [self hijacked_dataTaskWithRequest:request completionHandler:completionHandler];
    }
    
    // 使用修改后的请求
    return [self hijacked_dataTaskWithRequest:mutableRequest completionHandler:completionHandler];
}

@end

__attribute__((constructor))
static void initialize() {
    NSLog(@"[Hijack] URL Hijack Detector loaded - 域名改AppKey模式 | IP重定向+改AppKey模式");
}
