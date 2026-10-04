//go:build darwin && cgo

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include "http_darwin.h"

// One ephemeral session per request. Foundation owns delegate lifetime until
// invalidation completes, independently of the Go-side retained handle.
@interface OdooHTTPRequest : NSObject <NSURLSessionDataDelegate>
@property(nonatomic, strong) NSLock *lock;
@property(nonatomic, strong) NSURLSession *session;
@property(nonatomic, strong) NSURLSessionDataTask *task;
@property(nonatomic, strong) NSMutableData *pending;
@property(nonatomic, strong) NSData *body;
@property(nonatomic, strong) NSData *metadata;
@property(nonatomic, strong) NSHTTPURLResponse *response;
@property NSUInteger limit;
@property BOOL verifyTLS;
@property BOOL finished;
@end

@implementation OdooHTTPRequest
- (void)finish:(NSString *)error {
    [self.lock lock];
    if (!self.finished) {
        NSMutableDictionary *headers = [NSMutableDictionary dictionary];
        for (id key in self.response.allHeaderFields) {
            headers[[key description]] = [self.response.allHeaderFields[key] description];
        }
        NSDictionary *result = @{ @"status": @(self.response.statusCode), @"headers": headers, @"error": error ?: @"" };
        NSData *metadata = [NSJSONSerialization dataWithJSONObject:result options:0 error:nil];
        if (!metadata || metadata.length > 65536) {
            metadata = [@"{\"error\":\"native HTTP response headers exceed limit\"}" dataUsingEncoding:NSUTF8StringEncoding];
            error = @"header limit";
        }
        self.metadata = metadata;
        self.body = error ? [NSData data] : [self.pending copy];
        self.pending = nil;
        self.finished = YES;
    }
    [self.lock unlock];
}
- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task willPerformHTTPRedirection:(NSHTTPURLResponse *)response newRequest:(NSURLRequest *)request completionHandler:(void (^)(NSURLRequest *))completionHandler {
    // Never replay a credential-bearing request inside Foundation. Go owns
    // redirect decisions, including same-origin POST replay and hop limits.
    completionHandler(nil);
}
- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)task didReceiveResponse:(NSURLResponse *)response completionHandler:(void (^)(NSURLSessionResponseDisposition))completionHandler {
    if (![response isKindOfClass:[NSHTTPURLResponse class]]) {
        [self finish:@"native HTTP response is not HTTP"];
        completionHandler(NSURLSessionResponseCancel);
        return;
    }
    self.response = (NSHTTPURLResponse *)response;
    if (response.expectedContentLength > (long long)self.limit) {
        [self finish:@"native HTTP response exceeds 10 MiB"];
        completionHandler(NSURLSessionResponseCancel);
        return;
    }
    completionHandler(NSURLSessionResponseAllow);
}
- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)task didReceiveData:(NSData *)data {
    [self.lock lock];
    BOOL over = !self.finished && data.length > self.limit - self.pending.length;
    if (!self.finished && !over) [self.pending appendData:data];
    [self.lock unlock];
    if (over) {
        [self finish:@"native HTTP response exceeds 10 MiB"];
        [task cancel];
    }
}
- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error {
    // Never forward localized errors (which may contain URLs or secrets).
    [self finish:error ? [NSString stringWithFormat:@"native HTTP request failed (code %ld)", (long)error.code] : nil];
    [session finishTasksAndInvalidate];
    [self.lock lock];
    self.task = nil;
    self.session = nil;
    [self.lock unlock];
}
- (void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential *))completionHandler {
    if (!self.verifyTLS && [challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust] && challenge.protectionSpace.serverTrust) {
        // Only the existing explicit human verify_ssl=false setting permits this.
        completionHandler(NSURLSessionAuthChallengeUseCredential, [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust]);
    } else if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
    } else {
        // Do not obtain HTTP/client-certificate credentials from the OS.
        completionHandler(NSURLSessionAuthChallengeRejectProtectionSpace, nil);
    }
}
- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential *))completionHandler {
    [self URLSession:session didReceiveChallenge:challenge completionHandler:completionHandler];
}
@end

void *odoo_http_start(const char *url, const char *method, const char *headers,
                     const void *body, size_t length, double timeout,
                     size_t response_limit, int verify_tls) {
    @autoreleasepool {
        NSURL *target = [NSURL URLWithString:[NSString stringWithUTF8String:url]];
        if (!target) return NULL;
        NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:target];
        request.HTTPMethod = [NSString stringWithUTF8String:method];
        request.timeoutInterval = timeout;
        request.HTTPShouldHandleCookies = NO;
        NSDictionary *fields = [NSJSONSerialization JSONObjectWithData:[[NSString stringWithUTF8String:headers] dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
        if (![fields isKindOfClass:[NSDictionary class]]) return NULL;
        for (NSString *key in fields) {
            if ([key caseInsensitiveCompare:@"Content-Length"] == NSOrderedSame) continue;
            [request setValue:[fields[key] componentsJoinedByString:@", "] forHTTPHeaderField:key];
        }
        if (length) request.HTTPBody = [NSData dataWithBytes:body length:length];
        OdooHTTPRequest *state = [OdooHTTPRequest new];
        state.lock = [NSLock new];
        state.pending = [NSMutableData data];
        state.limit = response_limit;
        state.verifyTLS = verify_tls != 0;
        NSURLSessionConfiguration *config = [NSURLSessionConfiguration ephemeralSessionConfiguration];
        config.HTTPCookieStorage = nil;
        config.HTTPShouldSetCookies = NO;
        config.URLCredentialStorage = nil;
        config.URLCache = nil;
        config.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
        config.timeoutIntervalForRequest = timeout;
        config.timeoutIntervalForResource = timeout;
        NSOperationQueue *queue = [NSOperationQueue new];
        queue.maxConcurrentOperationCount = 1;
        state.session = [NSURLSession sessionWithConfiguration:config delegate:state delegateQueue:queue];
        state.task = [state.session dataTaskWithRequest:request];
        [state.task resume];
        return (__bridge_retained void *)state;
    }
}
int odoo_http_finished(void *handle) {
    OdooHTTPRequest *state = (__bridge OdooHTTPRequest *)handle;
    [state.lock lock];
    BOOL done = state.finished;
    [state.lock unlock];
    return done;
}
char *odoo_http_metadata(void *handle) {
    @autoreleasepool {
        OdooHTTPRequest *state = (__bridge OdooHTTPRequest *)handle;
        return strdup([[NSString alloc] initWithData:state.metadata encoding:NSUTF8StringEncoding].UTF8String);
    }
}
const void *odoo_http_body(void *handle, size_t *length) {
    OdooHTTPRequest *state = (__bridge OdooHTTPRequest *)handle;
    *length = state.body.length;
    return state.body.bytes;
}
void odoo_http_cancel(void *handle) {
    OdooHTTPRequest *state = (__bridge OdooHTTPRequest *)handle;
    [state.lock lock];
    NSURLSession *session = state.session;
    [state.lock unlock];
    [session invalidateAndCancel];
}
void odoo_http_release(void *handle) {
    @autoreleasepool { OdooHTTPRequest *state = (__bridge_transfer OdooHTTPRequest *)handle; (void)state; }
}
