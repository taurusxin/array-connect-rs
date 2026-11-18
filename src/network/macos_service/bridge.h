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
#define AC_SERVICE_ID AC_GUI_ID ".network"
#define AC_SERVICE_PLIST AC_SERVICE_ID ".plist"
#define AC_PROTOCOL 1
#define AC_REQUEST_LIMIT (256 * 1024)
#define AC_ERROR_LIMIT 512

enum ac_operation { AC_PROBE, AC_SETUP, AC_CLEANUP };
enum ac_status { AC_UNAVAILABLE, AC_NOT_REGISTERED, AC_APPROVAL_REQUIRED, AC_ENABLED };
typedef void (*ac_callback)(void *);
typedef int (*ac_setup)(void *, const uint8_t *, size_t, int *, char *);
typedef int (*ac_cleanup)(void *, char *);

static inline void ac_error(char *buffer, const char *message) {
    snprintf(buffer, AC_ERROR_LIMIT, "%s", message);
}

// Both sides pin an identifier and the Team ID of their own Developer ID
// signature. A self-signed or ad-hoc binary cannot qualify.
static inline NSString *ac_requirement(const char *identifier, NSString *team) {
    return [NSString stringWithFormat:
        @"anchor apple generic and identifier \"%s\" and "
         "certificate leaf[field.1.2.840.113635.100.6.1.13] exists and "
         "certificate leaf[subject.OU] = \"%@\"", identifier, team];
}

static inline NSString *ac_signing_team(const char *self_identifier) {
    SecCodeRef code = NULL;
    SecStaticCodeRef executable = NULL;
    CFDictionaryRef details = NULL;
    OSStatus status = SecCodeCopySelf(kSecCSDefaultFlags, &code);
    if (status == errSecSuccess) {
        status = SecCodeCopyStaticCode(code, kSecCSDefaultFlags, &executable);
    }
    if (status == errSecSuccess) {
        status = SecCodeCopySigningInformation(executable, kSecCSSigningInformation, &details);
    }
    NSString *team = nil;
    if (status == errSecSuccess) {
        NSDictionary *info = CFBridgingRelease(details);
        NSString *value = info[(__bridge NSString *)kSecCodeInfoTeamIdentifier];
        NSCharacterSet *invalid = [[NSCharacterSet characterSetWithCharactersInString:
            @"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"] invertedSet];
        if ([value isKindOfClass:[NSString class]] && value.length == 10 &&
            [value rangeOfCharacterFromSet:invalid].location == NSNotFound) {
            SecRequirementRef requirement = NULL;
            NSString *text = ac_requirement(self_identifier, value);
            if (SecRequirementCreateWithString((__bridge CFStringRef)text, kSecCSDefaultFlags,
                                               &requirement) == errSecSuccess) {
                if (SecCodeCheckValidity(code, kSecCSDefaultFlags, requirement) == errSecSuccess) {
                    team = value;
                }
                CFRelease(requirement);
            }
        }
    }
    if (executable != NULL) CFRelease(executable);
    if (code != NULL) CFRelease(code);
    return team;
}

#endif
