// SPDX-License-Identifier: AGPL-3.0-only
#define NHOVPN_TEST 1
#include "../Tweak.mm"
#include <assert.h>
#include <atomic>
#include <thread>
#include <vector>

static struct ifaddrs fixture[5];
static std::atomic<int> releases{0};
static NSInteger testVPNStatus;
static int32_t testSCStatus;
static NSInteger fakeVPNStatus(id, SEL) { return testVPNStatus; }
static int32_t fakeSCStatus(const void *) { return testSCStatus; }
static int fakeGet(struct ifaddrs **out) { *out = fixture; errno = EBUSY; return 0; }
static int fakeError(struct ifaddrs **) { errno = EACCES; return -1; }
static void fakeFree(struct ifaddrs *p) { assert(p == fixture); ++releases; }
static void setup(const char **names, size_t count) {
    memset(fixture, 0, sizeof(fixture));
    for (size_t i = 0; i < count; ++i) {
        fixture[i].ifa_name = (char *)names[i];
        fixture[i].ifa_next = i + 1 < count ? &fixture[i + 1] : nullptr;
        fixture[i].ifa_flags = (unsigned int)(i + 100);
    }
}
static struct if_nameindex *fakeNames(void) {
    auto *p = (struct if_nameindex *)calloc(4, sizeof(struct if_nameindex));
    p[0] = {1, strdup("utun0")}; p[1] = {2, strdup("en0")}; p[2] = {3, strdup("utun99")};
    errno = EBUSY; return p;
}
static void fakeFreeNames(struct if_nameindex *p) {
    assert(!strcmp(p[0].if_name, "utun0"));
    for (size_t i = 0; p[i].if_name; ++i) free(p[i].if_name);
    free(p); ++releases;
}
int main(void) {
    @autoreleasepool {
        for (const char *name : {"utun0", "utun99", "utun12345", "ipsec0", "ppp12", "tap", "tun9"})
            assert(tunnelName(name));
        for (const char *name : {"en0", "pdp_ip0", "lo0", "awdl0", "tunnel", "ipsecurity", "utunX", "", "bridge0"})
            assert(!tunnelName(name));
        assert(!tunnelName(nullptr));
        NSDictionary *input = @{@"HTTPEnable": @1, @"HTTPProxy": @"proxy.local", @"ExceptionsList": @[@"*.local"],
            @"ProxyAutoConfigURLString": @"https://proxy.local/pac", @"__SCOPED__": @{@"utun0": @{}, @"utun42": @{}, @"en0": @{@"HTTPEnable": @1}}};
        NSDictionary *output = sanitizeProxy(input);
        assert([output[@"HTTPProxy"] isEqual:input[@"HTTPProxy"]]);
        assert([output[@"ExceptionsList"] isEqual:input[@"ExceptionsList"]]);
        assert([output[@"ProxyAutoConfigURLString"] isEqual:input[@"ProxyAutoConfigURLString"]]);
        assert([output[@"__SCOPED__"] count] == 1);
        assert([input[@"__SCOPED__"] count] == 3);
        assert(sanitizeProxy(nil) == nil);
        assert([sanitizeProxy(@{}) isEqual:@{}]);
        assert([sanitizeProxy(@{@"__SCOPED__": @7}) isEqual:@{@"__SCOPED__": @7}]);
        originalGetAddresses = fakeGet; originalFreeAddresses = fakeFree;
        const char *mixed[] = {"utun0", "en0", "utun42", "pdp_ip0", "ppp2"}; setup(mixed, 5);
        struct ifaddrs *a, *b;
        assert(!replacedGetAddresses(&a) && errno == EBUSY);
        assert(!strcmp(a->ifa_name, "en0") && a->ifa_flags == 101);
        assert(!strcmp(a->ifa_next->ifa_name, "pdp_ip0") && !a->ifa_next->ifa_next);
        assert(fixture[0].ifa_next == &fixture[1]);
        assert(!replacedGetAddresses(&b) && a != b);
        replacedFreeAddresses(b); replacedFreeAddresses(a);
        assert(!allocations && releases == 2);
        std::vector<std::thread> threads;
        for (int i = 0; i < 8; ++i) threads.emplace_back([] {
            for (int j = 0; j < 1000; ++j) {
                struct ifaddrs *p; assert(!replacedGetAddresses(&p));
                assert(!strcmp(p->ifa_name, "en0")); replacedFreeAddresses(p);
            }
        });
        for (auto &thread : threads) thread.join();
        assert(!allocations && releases == 8002);
        const char *onlyTunnel[] = {"utun0", "ipsec2"}; setup(onlyTunnel, 2);
        assert(!replacedGetAddresses(&a) && !a && errno == EBUSY);
        const char *plain[] = {"en0", "pdp_ip0"}; setup(plain, 2);
        assert(!replacedGetAddresses(&a) && a == fixture); replacedFreeAddresses(a);
        originalGetAddresses = fakeError;
        assert(replacedGetAddresses(&a) == -1 && errno == EACCES);
        originalNameIndex = fakeNames; originalFreeNameIndex = fakeFreeNames;
        auto *names = replacedNameIndex();
        assert(errno == EBUSY && names[0].if_index == 2 && !strcmp(names[0].if_name, "en0"));
        assert(!names[1].if_index && !names[1].if_name);
        replacedFreeNameIndex(names); assert(!nameAllocations);
        originalVPNStatus = fakeVPNStatus; originalSCStatus = fakeSCStatus;
        for (NSInteger status = 0; status <= 6; ++status) {
            testVPNStatus = status;
            assert(replacedVPNStatus(nil, @selector(status)) == (status >= 2 && status <= 5 ? 1 : status));
        }
        for (int32_t status = -1; status <= 4; ++status) {
            testSCStatus = status;
            assert(replacedSCStatus(nullptr) == (status >= 1 && status <= 3 ? 0 : status));
        }
        puts("PASS: proxy preservation, prefix matching, head/middle/tail/all/no tunnels, ownership, errors, 8000 concurrent allocations");
    }
}
