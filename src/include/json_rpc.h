/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef MINK_JSON_RPC_HNDLR_H
#define MINK_JSON_RPC_HNDLR_H

#include <functional>
#include <nlohmann/json.hpp>

using json = nlohmann::basic_json<nlohmann::ordered_map>;

namespace json_rpc {
    class JsonRpc {
    public:
        explicit JsonRpc(const json &data);
        explicit JsonRpc(const json &&data) = delete;
        ~JsonRpc() = default;
        JsonRpc(const JsonRpc &o) = delete;
        JsonRpc &operator=(const JsonRpc &o) = delete;

        void verify(bool check_mink = false);
        const std::string &get_method() const;
        static int get_param_id(const std::string &p);
        const std::string get_data() const;
        void process_params(const std::function<bool(int id, const std::string &)> f) const;
        int get_method_id() const;
        static int get_method_id(const std::string &m);
        const json &get_params() const;
        int get_id() const;
        int get_mink_service_id() const;
        const std::string &get_auth_crdts() const;
        const std::string &get_mink_dtype() const;
        const std::string *get_mink_did() const;
        int get_mink_timeout() const;

        // static methods
        static json gen_err(const int code, const std::string &msg);
        static json gen_err(const int code,
                            const int id,
                            const std::string &msg);
        static json gen_err(const int code, const int id);
        static json gen_err(const int code);
        static json gen_response(int id);

        // string constants
        static const char *JSON_RPC_;
        static const char *VERSION_;
        static const char *METHOD_;
        static const char *PARAMS_;
        static const char *RESULT_;
        static const char *ID_;
        static const char *ERROR_;
        static const char *CODE_;
        static const char *MESSAGE_;
        // mink string constants
        static const char *MINK_SERVICE_ID_;
        static const char *MINK_DTYPE_;
        static const char *MINK_DID_;
        static const char *MINK_CREDENTIALS_;
        static const char *MINK_TIMEOUT_;

    private:
        // valid json rpc 2.0 message
        const json &data_;
        // verified
        bool verified_ = false;
        bool has_id_ = false;
        // mink params
        bool mink_verified_ = false;
        bool has_mink_service_ = false;
        bool has_mink_dtype_ = false;
        bool has_mink_did_ = false;
    };

} // namespace json_rpc

#endif /* ifndef MINK_JSON_RPC_HNDLR_H */
