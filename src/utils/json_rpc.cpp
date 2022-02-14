/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <iostream>
#include <json_rpc.h>
#include <gdt.pb.enums_only.h>
#include <stdexcept>

// static members
const char *json_rpc::JsonRpc::JSON_RPC_            = "jsonrpc";
const char *json_rpc::JsonRpc::VERSION_             = "2.0";
const char *json_rpc::JsonRpc::METHOD_              = "method";
const char *json_rpc::JsonRpc::PARAMS_              = "params";
const char *json_rpc::JsonRpc::RESULT_              = "result";
const char *json_rpc::JsonRpc::ID_                  = "id";
const char *json_rpc::JsonRpc::ERROR_               = "error";
const char *json_rpc::JsonRpc::CODE_                = "code";
const char *json_rpc::JsonRpc::MESSAGE_             = "message";
// mink string constants
const char *json_rpc::JsonRpc::MINK_SERVICE_ID_     = "MINK_SERVICE_ID";
const char *json_rpc::JsonRpc::MINK_DTYPE_          = "MINK_DTYPE";
const char *json_rpc::JsonRpc::MINK_DID_            = "MINK_DID";
const char *json_rpc::JsonRpc::MINK_CREDENTIALS_    = "MINK_CREDENTIALS";
const char *json_rpc::JsonRpc::MINK_TIMEOUT_        = "MINK_TIMEOUT";

json_rpc::JsonRpc::JsonRpc(const json &data) : data_(data){

}

json json_rpc::JsonRpc::gen_err(const int code, const std::string &msg){
    json j;
    j[JSON_RPC_] = const_cast<char*>(VERSION_);
    j[ERROR_][CODE_] = code;
    j[ERROR_][MESSAGE_] = msg;
    return j;
}

json json_rpc::JsonRpc::gen_err(const int code,
                                const int id,
                                const std::string &msg) {
    json j;
    j[JSON_RPC_] = const_cast<char*>(VERSION_);
    j[ERROR_][CODE_] = code;
    j[ERROR_][MESSAGE_] = msg;
    return j;
}

json json_rpc::JsonRpc::gen_err(const int code){
    json j;
    j[JSON_RPC_] = const_cast<char*>(VERSION_);
    j[ERROR_][CODE_] = code;
    return j;
}

json json_rpc::JsonRpc::gen_err(const int code, const int id){
    json j;
    j[JSON_RPC_] = const_cast<char*>(VERSION_);
    j[ERROR_][CODE_] = code;
    j[ID_] = id;
    return j;
}


json json_rpc::JsonRpc::gen_response(int id){
    json j;
    j[JSON_RPC_] = const_cast<char*>(VERSION_);
    j[ID_] = id;
    return j;
}


int json_rpc::JsonRpc::get_method_id(const std::string &m){
    auto it = std::find_if(gdt_grpc::SysagentCommandMap.cbegin(),
                           gdt_grpc::SysagentCommandMap.cend(),
                           [&m](const std::pair<int, std::string> &p) { 
                               return p.second == m; 
                           });
    if (it == gdt_grpc::SysagentCommandMap.cend())
        return -1;
    else
        return it->first;
}


int json_rpc::JsonRpc::get_method_id() const {
    const std::string &m = get_method();
    auto it = std::find_if(gdt_grpc::SysagentCommandMap.cbegin(),
                           gdt_grpc::SysagentCommandMap.cend(),
                           [&m](const std::pair<int, std::string> &p) { 
                               return p.second == m; 
                           });
    if (it == gdt_grpc::SysagentCommandMap.cend())
        return -1;
    else
        return it->first;
}

int json_rpc::JsonRpc::get_param_id(const std::string &p) {
    auto it = std::find_if(gdt_grpc::SysagentParamMap.cbegin(),
                           gdt_grpc::SysagentParamMap.cend(),
                           [&p](const std::pair<int, std::string> &pr) { 
                               return pr.second == p;
                           });
    if (it == gdt_grpc::SysagentParamMap.cend())
        return -1;
    else
        return it->first;

}

void json_rpc::JsonRpc::process_params(const std::function<bool(int id, const std::string &)> &f) const {
    if (!verified_)
        throw std::invalid_argument("unverified");

    // iterate
    json p = data_.at(PARAMS_);

    for(auto it = p.begin(); it != p.end(); ++it){
        // check for param id
        int id = get_param_id(it.key());
        if (id == -1)
            continue;

        // convert to string
        if (!(*it).is_string()) {
            // only non fractional
            if ((*it).is_number_unsigned() || (*it).is_number_integer()) {
                std::string s = std::to_string((*it).get_ref<const json::number_integer_t &>());
                f(id, s);
            }
        } else
            f(id, (*it).get_ref<const json::string_t &>());
    }
}

const std::string &json_rpc::JsonRpc::get_method() const {
    if (!verified_)
        throw std::invalid_argument("unverified");

    return data_.at(METHOD_).get_ref<const json::string_t&>();
}

const json &json_rpc::JsonRpc::get_params() const {
    if (!verified_)
        throw std::invalid_argument("unverified");

    return data_.at(PARAMS_);
}

static bool validate_id(const json &d){
    // id (optional)
    if (d.contains(json_rpc::JsonRpc::ID_)) {
        const json &j_id = d.at(json_rpc::JsonRpc::ID_);
        if (!(j_id.is_string() || j_id.is_number_integer()))
            throw std::invalid_argument("id != string | integer");

        return true;
    }
    return false;
}

int json_rpc::JsonRpc::get_mink_timeout() const {
    if (!mink_verified_)
        throw std::invalid_argument("MINK: unverified");

    // return timeout if found
    const auto &it = data_[PARAMS_].find(MINK_TIMEOUT_);
    // look for MINK_TIMEOUT_
    if (it == data_[PARAMS_].cend())
        return 2000;

    return it.value().get<json::number_unsigned_t>();
}

const std::string &json_rpc::JsonRpc::get_auth_crdts() const {
    if (!mink_verified_)
        throw std::invalid_argument("MINK: unverified");

    // return credentials
    const auto &it = data_[PARAMS_].find(MINK_CREDENTIALS_);
    // look for MINK_CREDENTIALS_
    if (it == data_[PARAMS_].cend())
        throw std::invalid_argument("MINK: MINK_CREDENTIALS parameter missing");

    return it.value().get_ref<const json::string_t &>();
}

int json_rpc::JsonRpc::get_mink_service_id() const {
    if (!mink_verified_)
        throw std::invalid_argument("MINK: unverified");

    // return id
    const auto &it = data_[PARAMS_].find(MINK_SERVICE_ID_);
    return it.value().get<json::number_unsigned_t>();
}

const std::string &json_rpc::JsonRpc::get_mink_dtype() const {
    if (!mink_verified_)
        throw std::invalid_argument("MINK: unverified");

    const auto &it = data_[PARAMS_].find(MINK_DTYPE_);
    return it.value().get_ref<const json::string_t&>();
}

const std::string *json_rpc::JsonRpc::get_mink_did() const {
    if (!mink_verified_)
        throw std::invalid_argument("MINK: unverified");

    const auto &it = data_[PARAMS_].find(MINK_DID_);
    if (it == data_[PARAMS_].end())
        return nullptr;
    else
        return (*it).get_ptr<const json::string_t *const>();
}


int json_rpc::JsonRpc::get_id() const {
    if (!verified_)
        throw std::invalid_argument("unverified");

    // get ID (string or int)
    // this will throw in case of a missing ID field
    const json &j_id = data_.at(json_rpc::JsonRpc::ID_);
    if (j_id.is_string())
        return std::stoi(data_.at(ID_).get<std::string>());
    else
        return (data_.at(ID_).get<int>());
}

void json_rpc::JsonRpc::verify(bool check_mink){
    // method
    const json &j_method = data_.at(METHOD_);
    if (!j_method.is_string())
        throw std::invalid_argument("method != string");
    // verify method
    auto it = gdt_grpc::SysagentCommandMap.cbegin();
    for (; it != gdt_grpc::SysagentCommandMap.cend(); ++it) {
        if (it->second == j_method)
            break;
    }
    if (it == gdt_grpc::SysagentCommandMap.cend())
        throw std::range_error("method not supported");

    // params
    const json &j_params = data_.at(PARAMS_);
    if (!(j_params.is_array() || j_params.is_object()))
        throw std::invalid_argument("params != object | array");

    // id (optional)
    try {
        has_id_ = validate_id(data_);
    } catch (std::invalid_argument &e) {
        throw;
    }

    // mink mandatory params
    // params cannot be an array
    if(check_mink){
        if (j_params.is_array())
            throw std::invalid_argument("MINK: params MUST be an object");

        // find service id (integer)
        auto it = j_params.find(MINK_SERVICE_ID_);
        if (it == j_params.end())
            throw std::invalid_argument("MINK: missing service id");
        if (!(*it).is_number_integer())
            throw std::invalid_argument("MINK: service id != integer");

        // find destination type
        it = j_params.find(MINK_DTYPE_);
        if (it == j_params.end())
            throw std::invalid_argument("MINK: missing destination type");
        if (!(*it).is_string())
            throw std::invalid_argument("MINK: destination type != string");

        // find destination id (optional)
        it = j_params.find(MINK_DID_);
        if (it != j_params.end() && !(*it).is_string())
            throw std::invalid_argument("MINK: destination id != string");

        // mink verified
        has_mink_service_ = true;
        has_mink_dtype_ = true;
        has_mink_did_ = true;
        mink_verified_ = true;
        verified_ = true;

    // rpc verified
    } else
        verified_ = true;
}
