/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef MINK_ERROR_CODE_H
#define MINK_ERROR_CODE_H

namespace mink {
    namespace error {
        enum ErrorCode {
            EC_OK                   =  0,
            EC_JSON_MALFORMED       = -1,
            EC_REQ_TIMEOUT          = -2,
            EC_GDT_PUSH_FAILED      = -3,
            EC_AUTH_INVALID_METHOD  = -4,
            EC_AUTH_FAILED          = -5,
            EC_UNKNOWN              = -9999
        };
    }
} // namespace mink

#endif /* ifndef MINK_ERROR_CODE_H */
