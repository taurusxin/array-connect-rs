#include "bridge.h"
#include <fcntl.h>

@interface ACLeaseLifetime : NSObject
@property (assign) void *context;
@property (assign) ac_callback failed;
@property (assign) ac_callback releaseContext;
@end

@implementation ACLeaseLifetime
- (void)dealloc { self.releaseContext(self.context); }
@end

int ac_protocol_version(void) {
    return AC_PROTOCOL;
}

bool ac_app_cdhash(char *hash) {
    @autoreleasepool {
        if (@available(macOS 13.0, *)) {
            return [NSBundle.mainBundle.bundleIdentifier isEqualToString:@AC_GUI_ID] &&
                ac_current_cdhash(AC_GUI_ID, hash);
        }
        return false;
    }
}

void *ac_client_open(const char *daemonHash, void *context, ac_callback failed,
                     ac_callback releaseContext) {
    @autoreleasepool {
        ACLeaseLifetime *lifetime = [ACLeaseLifetime new];
        lifetime.context = context;
        lifetime.failed = failed;
        lifetime.releaseContext = releaseContext;
        if (@available(macOS 13.0, *)) {
            xpc_connection_t peer = xpc_connection_create_mach_service(
                AC_SERVICE_ID, NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
            if (peer == NULL) return NULL;
            NSString *requirement = ac_requirement(AC_SERVICE_ID, daemonHash);
            if (xpc_connection_set_peer_code_signing_requirement(peer, requirement.UTF8String) != 0) {
                xpc_connection_cancel(peer);
                return NULL;
            }
            xpc_connection_set_event_handler(peer, ^(xpc_object_t event) {
                if (xpc_get_type(event) == XPC_TYPE_ERROR) {
                    lifetime.failed(lifetime.context);
                }
            });
            xpc_connection_activate(peer);
            return (__bridge_retained void *)peer;
        }
        return NULL;
    }
}

void ac_client_close(void *handle) {
    xpc_connection_t peer = (__bridge_transfer xpc_connection_t)handle;
    xpc_connection_cancel(peer);
}

int ac_client_request(void *handle, int operation, const uint8_t *data, size_t length,
                      int *descriptor, char *error) {
    @autoreleasepool {
        xpc_connection_t peer = (__bridge xpc_connection_t)handle;
        xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
        xpc_dictionary_set_int64(message, "version", AC_PROTOCOL);
        xpc_dictionary_set_int64(message, "operation", operation);
        if (length != 0) xpc_dictionary_set_data(message, "data", data, length);

        dispatch_semaphore_t signal = dispatch_semaphore_create(0);
        __block xpc_object_t reply = NULL;
        xpc_connection_send_message_with_reply(peer, message,
            dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^(xpc_object_t response) {
                reply = response;
                dispatch_semaphore_signal(signal);
            });
        int64_t seconds = operation == AC_PROBE ? 5 : 60;
        if (dispatch_semaphore_wait(signal, dispatch_time(DISPATCH_TIME_NOW, seconds * NSEC_PER_SEC)) != 0) {
            xpc_connection_cancel(peer);
            ac_error(error, "等待 macOS VPN 网络服务超时");
            return -1;
        }
        if (reply == NULL || xpc_get_type(reply) != XPC_TYPE_DICTIONARY) {
            xpc_connection_cancel(peer);
            ac_error(error, "无法连接已安装的 macOS VPN 网络服务");
            return -1;
        }
        if (xpc_dictionary_get_int64(reply, "version") != AC_PROTOCOL) {
            ac_error(error, "macOS VPN 网络服务协议版本不匹配");
            return AC_PROTOCOL_MISMATCH;
        }
        const char *cause = xpc_dictionary_get_string(reply, "error");
        if (cause != NULL) {
            ac_error(error, cause);
            return -1;
        }
        if (operation == AC_SETUP) {
            int fd = xpc_dictionary_dup_fd(reply, "utun");
            if (fd < 0 || fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
                if (fd >= 0) close(fd);
                xpc_connection_cancel(peer);
                ac_error(error, "macOS VPN 网络服务未返回有效的 utun 描述符");
                return -1;
            }
            *descriptor = fd;
        }
        return 0;
    }
}
