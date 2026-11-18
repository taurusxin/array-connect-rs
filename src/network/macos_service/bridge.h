#ifndef ARRAY_CONNECT_NETWORK_BRIDGE_H
#define ARRAY_CONNECT_NETWORK_BRIDGE_H

#include <Foundation/Foundation.h>
#include <Security/Security.h>
#include <dispatch/dispatch.h>
#include <xpc/xpc.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define AC_GUI_ID "com.taurusxin.arrayconnect"
#define AC_SERVICE_ID AC_GUI_ID ".vpnd"
#define AC_PROTOCOL 2
#define AC_REQUEST_LIMIT (256 * 1024)
#define AC_ERROR_LIMIT 512
#define AC_CDHASH_BYTES 20
#define AC_CDHASH_BUFFER (2 * AC_CDHASH_BYTES + 1)

enum ac_operation { AC_PROBE, AC_SETUP, AC_CLEANUP };
enum ac_request_result { AC_PROTOCOL_MISMATCH = -2 };
typedef void (*ac_callback)(void *);
typedef int (*ac_setup)(void *, const uint8_t *, size_t, int *, char *);
typedef int (*ac_cleanup)(void *, char *);

static inline void ac_error(char *buffer, const char *message) {
    snprintf(buffer, AC_ERROR_LIMIT, "%s", message);
}

static inline NSString *ac_requirement(const char *identifier, const char *hash) {
    return [NSString stringWithFormat:
        @"identifier \"%s\" and cdhash H\"%s\"", identifier, hash];
}

static inline bool ac_current_cdhash(const char *identifier, char *output) {
    SecCodeRef code = NULL;
    if (SecCodeCopySelf(kSecCSDefaultFlags, &code) != errSecSuccess) return false;
    SecStaticCodeRef executable = NULL;
    CFDictionaryRef details = NULL;
    bool valid = false;
    if (SecCodeCopyStaticCode(code, kSecCSDefaultFlags, &executable) == errSecSuccess &&
        SecCodeCopySigningInformation(executable, kSecCSSigningInformation, &details) == errSecSuccess) {
        NSDictionary *info = CFBridgingRelease(details);
        NSData *hash = info[(__bridge NSString *)kSecCodeInfoUnique];
        if ([hash isKindOfClass:[NSData class]] && hash.length == AC_CDHASH_BYTES) {
            const uint8_t *bytes = hash.bytes;
            for (size_t i = 0; i < AC_CDHASH_BYTES; i++) {
                snprintf(output + 2 * i, 3, "%02x", (unsigned)bytes[i]);
            }
            SecRequirementRef requirement = NULL;
            NSString *text = ac_requirement(identifier, output);
            if (SecRequirementCreateWithString((__bridge CFStringRef)text, kSecCSDefaultFlags,
                                               &requirement) == errSecSuccess) {
                valid = SecCodeCheckValidity(code, kSecCSDefaultFlags, requirement) == errSecSuccess;
                CFRelease(requirement);
            }
        }
    }
    if (executable != NULL) CFRelease(executable);
    CFRelease(code);
    return valid;
}

#endif
