// NeverHeardOfVPNs, thatmarcel; ratu.sh changes 2026-10-18.
// SPDX-License-Identifier: AGPL-3.0-only
#import <Foundation/Foundation.h>
#import <CFNetwork/CFNetwork.h>
#import <Network/Network.h>
#import <NetworkExtension/NetworkExtension.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <pthread.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#ifndef NHOVPN_TEST
#include <substrate.h>
#endif

// Apple frameworks use the same APIs to maintain real connectivity. Mask only
// requests from application/embedded SDK code, never internal network-stack calls.
static bool clientCaller(const void *address) {
    Dl_info info = {};
    if (!dladdr(address, &info) || !info.dli_fname) return true;
    const char *path = info.dli_fname;
    return strncmp(path, "/System/", 8) && strncmp(path, "/usr/lib/", 9)
        && !strstr(path, "/System/Library/");
}

static bool tunnelName(const char *name) {
    if (!name) return false;
    const char *prefixes[] = {"utun", "ipsec", "ppp", "tap", "tun"};
    for (const char *prefix : prefixes) {
        size_t n = strlen(prefix);
        if (strncmp(name, prefix, n)) continue;
        const char *suffix = name + n;
        if (!*suffix) return true;
        bool digits = true;
        for (const char *p = suffix; *p; ++p)
            if (*p < '0' || *p > '9') { digits = false; break; }
        if (digits) return true;
    }
    return false;
}

// Preserve every non-tunnel setting, including PAC, explicit proxies and exceptions.
static NSDictionary *sanitizeProxy(NSDictionary *settings) {
    if (![settings isKindOfClass:NSDictionary.class]) return settings;
    id scoped = settings[@"__SCOPED__"];
    if (![scoped isKindOfClass:NSDictionary.class]) return settings;
    NSMutableDictionary *filtered = [scoped mutableCopy];
    for (id key in scoped) {
        if ([key isKindOfClass:NSString.class] && tunnelName([key UTF8String]))
            [filtered removeObjectForKey:key];
    }
    NSMutableDictionary *result = [settings mutableCopy];
    result[@"__SCOPED__"] = filtered;
    return result;
}

static CFDictionaryRef (*originalProxy)(void);
static CFDictionaryRef replacedProxy(void) {
    CFDictionaryRef value = originalProxy();
    if (!clientCaller(__builtin_return_address(0))) return value;
    if (!value) return nullptr;
    NSDictionary *settings = CFBridgingRelease(value);
    return (__bridge_retained CFDictionaryRef)sanitizeProxy(settings);
}

// Darwin does not promise individually allocated ifaddrs nodes. Keep the original
// allocation intact until freeifaddrs; clone only visible nodes, borrowing their fields.
struct AddressAllocation {
    AddressAllocation *next;
    struct ifaddrs *original;
    struct ifaddrs *visible;
};
static AddressAllocation *allocations;
static pthread_mutex_t allocationLock = PTHREAD_MUTEX_INITIALIZER;
static int (*originalGetAddresses)(struct ifaddrs **);
static void (*originalFreeAddresses)(struct ifaddrs *);

static int replacedGetAddresses(struct ifaddrs **out) {
    int rc = originalGetAddresses(out);
    int saved = errno;
    if (!clientCaller(__builtin_return_address(0))) { errno = saved; return rc; }
    if (rc || !out || !*out) { errno = saved; return rc; }
    size_t count = 0, hidden = 0;
    for (struct ifaddrs *p = *out; p; p = p->ifa_next)
        tunnelName(p->ifa_name) ? ++hidden : ++count;
    if (!hidden) { errno = saved; return rc; }
    if (!count) {
        originalFreeAddresses(*out); *out = nullptr; errno = saved; return rc;
    }
    AddressAllocation *record = (AddressAllocation *)calloc(1, sizeof(*record));
    struct ifaddrs *nodes = (struct ifaddrs *)calloc(count, sizeof(*nodes));
    if (!record || !nodes) {
        free(record); free(nodes); errno = saved; return rc; // Preserve connectivity on OOM.
    }
    size_t i = 0;
    for (struct ifaddrs *p = *out; p; p = p->ifa_next) {
        if (tunnelName(p->ifa_name)) continue;
        nodes[i] = *p;
        nodes[i].ifa_next = i + 1 < count ? &nodes[i + 1] : nullptr;
        ++i;
    }
    record->original = *out; record->visible = nodes;
    pthread_mutex_lock(&allocationLock);
    record->next = allocations; allocations = record;
    pthread_mutex_unlock(&allocationLock);
    *out = nodes; errno = saved; return rc;
}

static void replacedFreeAddresses(struct ifaddrs *head) {
    int saved = errno;
    AddressAllocation *found = nullptr;
    pthread_mutex_lock(&allocationLock);
    AddressAllocation **link = &allocations;
    while (*link) {
        if ((*link)->visible == head) { found = *link; *link = found->next; break; }
        link = &(*link)->next;
    }
    pthread_mutex_unlock(&allocationLock);
    if (found) {
        originalFreeAddresses(found->original); free(found->visible); free(found);
    } else if (head) originalFreeAddresses(head);
    errno = saved;
}

// Preserve the allocator's ownership contract for if_nameindex as well.
struct NameAllocation {
    NameAllocation *next;
    struct if_nameindex *original;
    struct if_nameindex *visible;
};
static NameAllocation *nameAllocations;
static struct if_nameindex *(*originalNameIndex)(void);
static void (*originalFreeNameIndex)(struct if_nameindex *);
static struct if_nameindex *replacedNameIndex(void) {
    struct if_nameindex *items = originalNameIndex();
    int saved = errno;
    if (!clientCaller(__builtin_return_address(0))) { errno = saved; return items; }
    if (!items) return items;
    size_t count = 0, hidden = 0;
    for (size_t i = 0; items[i].if_index || items[i].if_name; ++i)
        tunnelName(items[i].if_name) ? ++hidden : ++count;
    if (!hidden) { errno = saved; return items; }
    NameAllocation *record = (NameAllocation *)calloc(1, sizeof(*record));
    struct if_nameindex *visible = (struct if_nameindex *)calloc(count + 1, sizeof(*visible));
    if (!record || !visible) { free(record); free(visible); errno = saved; return items; }
    size_t write = 0;
    for (size_t i = 0; items[i].if_index || items[i].if_name; ++i) {
        if (!tunnelName(items[i].if_name)) visible[write++] = items[i];
    }
    record->original = items; record->visible = visible;
    pthread_mutex_lock(&allocationLock);
    record->next = nameAllocations; nameAllocations = record;
    pthread_mutex_unlock(&allocationLock);
    errno = saved; return visible;
}
static void replacedFreeNameIndex(struct if_nameindex *items) {
    int saved = errno;
    NameAllocation *found = nullptr;
    pthread_mutex_lock(&allocationLock);
    NameAllocation **link = &nameAllocations;
    while (*link) {
        if ((*link)->visible == items) { found = *link; *link = found->next; break; }
        link = &(*link)->next;
    }
    pthread_mutex_unlock(&allocationLock);
    if (found) {
        originalFreeNameIndex(found->original); free(found->visible); free(found);
    } else if (items) originalFreeNameIndex(items);
    errno = saved;
}

static bool hiddenInterface(nw_interface_t interface) {
    return interface && tunnelName(nw_interface_get_name(interface));
}
static void (*originalEnumerate)(nw_path_t, nw_path_enumerate_interfaces_block_t);
static void replacedEnumerate(nw_path_t path, nw_path_enumerate_interfaces_block_t block) {
    if (!clientCaller(__builtin_return_address(0))) { originalEnumerate(path, block); return; }
    if (!block) { originalEnumerate(path, block); return; }
    originalEnumerate(path, ^bool(nw_interface_t interface) {
        return hiddenInterface(interface) ? true : block(interface);
    });
}
static bool (*originalUsesType)(nw_path_t, nw_interface_type_t);
static bool replacedUsesType(nw_path_t path, nw_interface_type_t type) {
    bool result = originalUsesType(path, type);
    if (!clientCaller(__builtin_return_address(0))) return result;
    if (!result || type != nw_interface_type_other) return result;
    __block bool tunnel = false, visibleOther = false;
    originalEnumerate(path, ^bool(nw_interface_t interface) {
        if (hiddenInterface(interface)) tunnel = true;
        else if (nw_interface_get_type(interface) == nw_interface_type_other) visibleOther = true;
        return true;
    });
    return tunnel && !visibleOther ? false : result;
}

static NSInteger (*originalVPNStatus)(id, SEL);
static NSInteger replacedVPNStatus(id connection, SEL selector) {
    NSInteger status = originalVPNStatus(connection, selector);
    if (!clientCaller(__builtin_return_address(0))) return status;
    // Preserve invalid (0), disconnected (1), and unknown future enum values.
    return status >= 2 && status <= 5 ? 1 : status;
}
// Resolve the legacy SystemConfiguration API dynamically: it is not part of the
// supported iOS headers on every SDK, and an absent symbol must remain harmless.
static int32_t (*originalSCStatus)(const void *);
static int32_t replacedSCStatus(const void *connection) {
    int32_t status = originalSCStatus(connection);
    if (!clientCaller(__builtin_return_address(0))) return status;
    return status >= 1 && status <= 3 ? 0 : status;
}

#ifndef NHOVPN_TEST
static bool eligibleProcess(void) {
    NSBundle *bundle = NSBundle.mainBundle;
    // Test probe is distributed separately, never injected into arbitrary daemons.
    if ([NSProcessInfo.processInfo.processName isEqualToString:@"nhovpn-probe"]) return true;
    if (![bundle.bundlePath.pathExtension isEqualToString:@"app"]) return false;
    if ([bundle.bundleIdentifier hasPrefix:@"com.apple."]) return false;
    // VPN owners must retain visibility of their tunnel. Extension processes are
    // already excluded above. Also exclude container apps with NetworkExtension providers.
    NSString *plugins = [bundle.bundlePath stringByAppendingPathComponent:@"PlugIns"];
    for (NSString *entry in [NSFileManager.defaultManager contentsOfDirectoryAtPath:plugins error:nil]) {
        NSBundle *extension = [NSBundle bundleWithPath:[plugins stringByAppendingPathComponent:entry]];
        NSString *point = extension.infoDictionary[@"NSExtension"][@"NSExtensionPointIdentifier"];
        if ([point isKindOfClass:NSString.class] && [point hasPrefix:@"com.apple.networkextension."])
            return false;
    }
    return true;
}
static void installHook(const char *name, void *replacement, void **original) {
    void *symbol = dlsym(RTLD_DEFAULT, name);
    if (symbol) MSHookFunction(symbol, replacement, original);
}
__attribute__((constructor)) static void initialize(void) {
    @autoreleasepool {
        if (!eligibleProcess()) return;
        installHook("CFNetworkCopySystemProxySettings", (void *)replacedProxy, (void **)&originalProxy);
        // Install the deallocator first so every filtered list has a valid release path.
        installHook("freeifaddrs", (void *)replacedFreeAddresses, (void **)&originalFreeAddresses);
        if (originalFreeAddresses)
            installHook("getifaddrs", (void *)replacedGetAddresses, (void **)&originalGetAddresses);
        installHook("if_freenameindex", (void *)replacedFreeNameIndex, (void **)&originalFreeNameIndex);
        if (originalFreeNameIndex)
            installHook("if_nameindex", (void *)replacedNameIndex, (void **)&originalNameIndex);
        installHook("nw_path_enumerate_interfaces", (void *)replacedEnumerate, (void **)&originalEnumerate);
        if (originalEnumerate)
            installHook("nw_path_uses_interface_type", (void *)replacedUsesType, (void **)&originalUsesType);
        Class connection = NSClassFromString(@"NEVPNConnection");
        if (connection && class_getInstanceMethod(connection, @selector(status)))
            MSHookMessageEx(connection, @selector(status), (IMP)replacedVPNStatus, (IMP *)&originalVPNStatus);
        installHook("SCNetworkConnectionGetStatus", (void *)replacedSCStatus, (void **)&originalSCStatus);
    }
}
#endif
