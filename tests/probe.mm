// SPDX-License-Identifier: AGPL-3.0-only
#import <Foundation/Foundation.h>
#import <CFNetwork/CFNetwork.h>
#import <Network/Network.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <dlfcn.h>
#include <stdio.h>
#include <CommonCrypto/CommonDigest.h>
int main(int argc, char **argv) {
    @autoreleasepool {
        if (argc == 2) {
            if (!dlopen(argv[1], RTLD_NOW | RTLD_GLOBAL)) { fprintf(stderr, "%s\n", dlerror()); return 2; }
        }
        NSMutableDictionary *report = [NSMutableDictionary dictionary];
        NSMutableArray *addresses = [NSMutableArray array], *names = [NSMutableArray array];
        struct ifaddrs *head = nullptr;
        int rc = getifaddrs(&head); report[@"getifaddrs_rc"] = @(rc);
        if (!rc) {
            for (struct ifaddrs *p = head; p; p = p->ifa_next)
                if (p->ifa_name && ![addresses containsObject:@(p->ifa_name)]) [addresses addObject:@(p->ifa_name)];
            freeifaddrs(head);
        }
        report[@"getifaddrs"] = addresses;
        struct if_nameindex *indices = if_nameindex();
        if (indices) {
            for (size_t i = 0; indices[i].if_name; ++i) [names addObject:@(indices[i].if_name)];
            if_freenameindex(indices);
        }
        report[@"if_nameindex"] = names;
        NSDictionary *settings = CFBridgingRelease(CFNetworkCopySystemProxySettings());
        report[@"proxy_scoped"] = [settings[@"__SCOPED__"] allKeys] ?: @[];
        dispatch_semaphore_t ready = dispatch_semaphore_create(0);
        nw_path_monitor_t monitor = nw_path_monitor_create();
        nw_path_monitor_set_queue(monitor, dispatch_queue_create("sh.ratu.nhovpn.probe", DISPATCH_QUEUE_SERIAL));
        __block NSDictionary *pathResult;
        nw_path_monitor_set_update_handler(monitor, ^(nw_path_t path) {
            if (pathResult) return;
            NSMutableArray *interfaces = [NSMutableArray array];
            nw_path_enumerate_interfaces(path, ^bool(nw_interface_t interface) {
                const char *name = nw_interface_get_name(interface);
                [interfaces addObject:@{@"name": name ? @(name) : @"", @"type": @(nw_interface_get_type(interface))}];
                return true;
            });
            pathResult = @{@"interfaces": interfaces, @"other": @(nw_path_uses_interface_type(path, nw_interface_type_other)),
                @"wifi": @(nw_path_uses_interface_type(path, nw_interface_type_wifi)),
                @"cellular": @(nw_path_uses_interface_type(path, nw_interface_type_cellular)), @"status": @(nw_path_get_status(path))};
            dispatch_semaphore_signal(ready);
        });
        nw_path_monitor_start(monitor);
        long timeout = dispatch_semaphore_wait(ready, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));
        nw_path_monitor_cancel(monitor);
        report[@"path"] = timeout ? @{@"timeout": @YES} : pathResult;
        for (int i = 0; i < 2000; ++i) { struct ifaddrs *p = nullptr; if (!getifaddrs(&p)) freeifaddrs(p); }
        report[@"allocation_cycles"] = @2000;
        // Verify real HTTPS transfer from the same process whose APIs are masked.
        // Hash the IP response so validation never publishes the user's exit address.
        dispatch_semaphore_t downloaded = dispatch_semaphore_create(0);
        NSURLSessionConfiguration *config = NSURLSessionConfiguration.ephemeralSessionConfiguration;
        config.timeoutIntervalForRequest = 15;
        NSURLSession *session = [NSURLSession sessionWithConfiguration:config];
        __block NSDictionary *transfer;
        NSURL *url = [NSURL URLWithString:@"https://api.ipify.org?format=json"];
        [[session dataTaskWithURL:url completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            NSInteger status = [response isKindOfClass:NSHTTPURLResponse.class] ? [(NSHTTPURLResponse *)response statusCode] : 0;
            NSDictionary *json = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;
            NSString *ip = [json isKindOfClass:NSDictionary.class] ? json[@"ip"] : nil;
            NSMutableString *fingerprint = [NSMutableString string];
            if ([ip isKindOfClass:NSString.class]) {
                NSData *value = [ip dataUsingEncoding:NSUTF8StringEncoding];
                unsigned char digest[CC_SHA256_DIGEST_LENGTH]; CC_SHA256(value.bytes, (CC_LONG)value.length, digest);
                for (unsigned char byte : digest) [fingerprint appendFormat:@"%02x", byte];
            }
            transfer = @{@"http_status": @(status), @"bytes": @(data.length), @"egress_sha256": fingerprint,
                @"error_code": @(error ? error.code : 0)};
            dispatch_semaphore_signal(downloaded);
        }] resume];
        long transferTimeout = dispatch_semaphore_wait(downloaded, dispatch_time(DISPATCH_TIME_NOW, 20 * NSEC_PER_SEC));
        [session invalidateAndCancel];
        report[@"transfer"] = transferTimeout ? @{@"timeout": @YES} : transfer;
        NSData *data = [NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingPrettyPrinted error:nil];
        fwrite(data.bytes, 1, data.length, stdout); putchar('\n');
        return timeout || transferTimeout ? 3 : 0;
    }
}
