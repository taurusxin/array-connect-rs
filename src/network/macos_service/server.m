#include "bridge.h"
#include <SystemConfiguration/SystemConfiguration.h>
#include <os/log.h>
#include <signal.h>

static NSMutableArray<NSString *> *ac_strings(const char *const *values, size_t count) {
    NSMutableArray<NSString *> *strings = [NSMutableArray arrayWithCapacity:count];
    for (size_t i = 0; i < count; i++) {
        NSString *value = [NSString stringWithUTF8String:values[i]];
        if (value == nil) return nil;
        [strings addObject:value];
    }
    return strings;
}

void *ac_dns_open(const char *key, const char *interface, const char *const *servers,
                  size_t serverCount, const char *const *search, size_t searchCount) {
    @autoreleasepool {
        NSString *name = [NSString stringWithUTF8String:interface];
        NSString *storeKey = [NSString stringWithUTF8String:key];
        NSArray *addresses = ac_strings(servers, serverCount);
        NSArray *domains = ac_strings(search, searchCount);
        if (name == nil || storeKey == nil || addresses == nil || domains == nil) return NULL;
        NSDictionary *dns = @{
            @"ServerAddresses": addresses,
            @"InterfaceName": name,
            @"SupplementalMatchDomains": @[@""],
            @"SupplementalMatchOrders": @[@1],
            @"SearchDomains": domains,
        };
        SCDynamicStoreRef store = SCDynamicStoreCreate(
            NULL, CFSTR("Array Connect VPN Network Service"), NULL, NULL);
        if (store == NULL) return NULL;
        if (!SCDynamicStoreAddTemporaryValue(store, (__bridge CFStringRef)storeKey,
                                             (__bridge CFDictionaryRef)dns)) {
            CFRelease(store);
            return NULL;
        }
        return store;
    }
}

void ac_dns_close(void *store) {
    CFRelease(store);
}

static bool ac_console_user(xpc_connection_t peer) {
    uid_t uid = 0;
    CFStringRef user = SCDynamicStoreCopyConsoleUser(NULL, &uid, NULL);
    if (user == NULL) return false;
    CFRelease(user);
    return uid != 0 && uid == xpc_connection_get_euid(peer);
}

bool ac_daemon_cdhash(char *hash) {
    @autoreleasepool {
        return ac_current_cdhash(AC_SERVICE_ID, hash);
    }
}

int ac_daemon_run(const char *clientHash, void *context, ac_setup setup, ac_cleanup cleanup) {
    @autoreleasepool {
        if (@available(macOS 13.0, *)) {
            if (geteuid() != 0) return -1;
            NSString *requirement = ac_requirement(AC_GUI_ID, clientHash);
            dispatch_queue_t queue = dispatch_queue_create(AC_SERVICE_ID, DISPATCH_QUEUE_SERIAL);
            static xpc_connection_t listener;
            listener = xpc_connection_create_mach_service(
                AC_SERVICE_ID, queue, XPC_CONNECTION_MACH_SERVICE_LISTENER);
            if (listener == NULL) return -1;

            // All lease ownership and the Rust rollback journal are confined to this queue.
            __block xpc_connection_t owner = NULL;
            signal(SIGTERM, SIG_IGN);
            static dispatch_source_t stop;
            stop = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGTERM, 0, queue);
            dispatch_source_set_event_handler(stop, ^{
                char error[AC_ERROR_LIMIT] = {0};
                if (cleanup(context, error) != 0) {
                    os_log_error(OS_LOG_DEFAULT, "VPN network service shutdown cleanup failed: %{public}s", error);
                }
                exit(0);
            });
            dispatch_activate(stop);

            xpc_connection_set_event_handler(listener, ^(xpc_object_t connection) {
                if (xpc_get_type(connection) != XPC_TYPE_CONNECTION) return;
                xpc_connection_t peer = (xpc_connection_t)connection;
                if (xpc_connection_set_peer_code_signing_requirement(peer, requirement.UTF8String) != 0) {
                    xpc_connection_cancel(peer);
                    return;
                }
                xpc_connection_set_target_queue(peer, queue);
                __weak xpc_connection_t accepted = peer;
                xpc_connection_set_event_handler(peer, ^(xpc_object_t message) {
                    xpc_connection_t peer = accepted;
                    if (peer == NULL) return;
                    char error[AC_ERROR_LIMIT] = {0};
                    if (xpc_get_type(message) == XPC_TYPE_ERROR) {
                        if (owner == peer) {
                            if (cleanup(context, error) != 0) {
                                os_log_error(OS_LOG_DEFAULT, "VPN network service peer cleanup failed: %{public}s", error);
                            }
                            owner = NULL;
                        }
                        if (message != XPC_ERROR_CONNECTION_INVALID) xpc_connection_cancel(peer);
                        return;
                    }
                    if (xpc_get_type(message) != XPC_TYPE_DICTIONARY) return;
                    xpc_object_t reply = xpc_dictionary_create_reply(message);
                    if (reply == NULL) return;
                    xpc_dictionary_set_int64(reply, "version", AC_PROTOCOL);
                    xpc_object_t operation = xpc_dictionary_get_value(message, "operation");
                    if (xpc_dictionary_get_int64(message, "version") != AC_PROTOCOL ||
                        operation == NULL || xpc_get_type(operation) != XPC_TYPE_INT64) {
                        ac_error(error, "macOS VPN 网络服务协议不匹配");
                    } else {
                        switch (xpc_int64_get_value(operation)) {
                            case AC_PROBE:
                                if (!ac_console_user(peer)) {
                                    ac_error(error, "只有当前登录的 macOS 用户可以使用 VPN 网络服务");
                                }
                                break;
                            case AC_SETUP: {
                                size_t length = 0;
                                const uint8_t *data = xpc_dictionary_get_data(message, "data", &length);
                                if (!ac_console_user(peer)) {
                                    ac_error(error, "只有当前登录的 macOS 用户可以建立 VPN");
                                } else if (owner != NULL) {
                                    ac_error(error, "macOS VPN 网络服务正在处理另一份网络配置");
                                } else if (data == NULL || length == 0 || length > AC_REQUEST_LIMIT) {
                                    ac_error(error, "VPN 网络配置请求大小无效");
                                } else {
                                    int fd = -1;
                                    // Keep ownership after a partial failure so the client
                                    // or the disconnect handler can retry cleanup.
                                    owner = peer;
                                    if (setup(context, data, length, &fd, error) == 0 && fd >= 0) {
                                        xpc_dictionary_set_fd(reply, "utun", fd);
                                    }
                                    if (fd >= 0) close(fd);
                                }
                                break;
                            }
                            case AC_CLEANUP:
                                if (owner == peer && cleanup(context, error) == 0) {
                                    owner = NULL;
                                }
                                break;
                            default:
                                ac_error(error, "macOS VPN 网络服务操作无效");
                        }
                    }
                    if (error[0] != '\0') xpc_dictionary_set_string(reply, "error", error);
                    xpc_connection_send_message(peer, reply);
                });
                xpc_connection_activate(peer);
            });
            xpc_connection_activate(listener);
            dispatch_main();
        }
        return -1;
    }
}
