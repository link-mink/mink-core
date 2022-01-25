/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef MINK_WS_SERVER_H
#define MINK_WS_SERVER_H

#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/buffers_iterator.hpp>
#include <boost/optional.hpp>
#include <boost/beast/core/detail/base64.hpp>
#include <algorithm>
#include <cstdlib>
#include <ctime>
#include <functional>
#include <memory>
#include <thread>
#include <json_rpc.h>
#include <gdt_utils.h>
#include <chrono>
#include <atomic>
#include <mink_err_codes.h>
#include "jrpc.h"
#include <gdt.pb.enums_only.h>
#include <vector>


// boost beast/asio
namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
namespace base64 = boost::beast::detail::base64;
namespace stdc = std::chrono;
using tcp = boost::asio::ip::tcp;
using Jrpc = json_rpc::JsonRpc;
using usr_info_t = std::tuple<std::string,      // username
                              int,              // user flags
                              WebSocketBase *,  // connection pointer
                              uint64_t>;        // last timestamp

//using wss = websocket::stream<beast::ssl_stream<beast::tcp_stream>>;
class WebSocketBase;


/**************/
/* Exceptions */
/**************/
class AuthException : public std::exception {
public:
    AuthException(const int ec) : ec_(ec){}
    ~AuthException() = default;

    const int get_ec() const { return ec_; }

private:
    int ec_;

};

class GDTException : public std::exception {
public:
    const char *what() const throw() { return "GDT push error!"; }
};

/**************************/
/* GDT push user callback */
/**************************/
class EVUserCB: public gdt::GDTCallbackMethod {
public:
    EVUserCB() = default;
    ~EVUserCB() = default;
    EVUserCB(const EVUserCB &o) = delete;
    EVUserCB &operator=(const EVUserCB &o) = delete;
    // param map for non-variant params
    std::vector<gdt::ServiceParam*> pmap;
    std::deque<std::string> buff;
};

/******************/
/* Helper methods */
/******************/
void fail(beast::error_code ec, char const *what);
//bool user_auth_prepare(boost::string_view &auth_str, int type);
//std::tuple<std::string, std::string, bool, int> user_auth(boost::string_view &auth_hdr);
std::tuple<int, std::string, std::string, int, int> user_auth_jrpc(const std::string &crdt);

/*******************************/
/* List of authenticated users */
/*******************************/
struct UserBanInfo {
    std::string username;
    int attemtps;
    uint64_t ts_msec;
    uint64_t ts_banned_until;
    bool banned;
};

class UserList {
public:
    UserList() = default;
    ~UserList() = default;
    UserList(const UserList &o) = delete;
    const UserList &operator=(const UserList &o) = delete;

    usr_info_t exists(const std::string &u);
    bool add(const usr_info_t &u);
    UserBanInfo *add_attempt(const std::string &u);
    UserBanInfo *get_banned(const std::string &u);
    void lift_ban(const std::string &u);
    void remove(const std::string &u, const uint64_t &ts);
    void remove_all();
    void process_all(const std::function<void(const usr_info_t &)> &f);
    std::size_t count();

private:
    std::mutex m;
    std::vector<usr_info_t> users;
    std::map<std::string, UserBanInfo> ban_lst;
};

/*************/
/* User list */
/*************/
extern UserList USERS;

/*****************/
/* WebSocketBase */
/*****************/
class WebSocketBase {
public:
    WebSocketBase() : usr_info_{"", 0, nullptr, 0} {}

#ifndef ENABLE_WS_SINGLE_SESSION
    ~WebSocketBase() = default;
#else
    ~WebSocketBase() {
        USERS.remove(std::get<0>(usr_info_), std::get<3>(usr_info_));
    }

#endif
    virtual beast::flat_buffer &get_buffer() = 0;
    virtual std::mutex &get_mtx() = 0;
    virtual void async_buffer_send(const std::string &d) = 0;
    virtual void do_close() = 0;

    usr_info_t usr_info_;
};

/**********************************/
/* Web Socket Session (ws or wss) */
/**********************************/
// the same code works with both SSL streams and regular sockets.
template <class Derived>
class WebSocketSession : public WebSocketBase {
public:
    WebSocketSession(): reading_{false} {}

    // Access the derived class
    Derived &derived(){
        return static_cast<Derived &>(*this);
    }

    // Start the asynchronous operation
    template<class Body, class Allocator>
    void do_accept(http::request<Body, http::basic_fields<Allocator>> req){
        // Set suggested timeout settings for the websocket
        derived().ws().set_option(websocket::stream_base::timeout::suggested(beast::role_type::server));

        // set nax nessage size
        derived().ws().read_message_max(0);

        // Set a decorator to change the Server of the handshake
        derived().ws().set_option(websocket::stream_base::decorator([](websocket::response_type &res) {
            res.set(http::field::server,
                    std::string(BOOST_BEAST_VERSION_STRING) +
                    " mink-ws");
            }));

        // Accept the websocket handshake
        derived().ws().async_accept(req,
                                    beast::bind_front_handler(&WebSocketSession::on_accept,
                                                              derived().shared_from_this()));
    }
    void on_accept(beast::error_code ec){
        if (ec)
            return fail(ec, "WebSocketSession::accept");

        // Read a message
        do_read();
    }
    void do_read(){
        // reading in progress, skip
        if(reading_.load()) return;

        // reading started
        reading_.store(true);

        // Read a message into our buffer
        derived().ws().async_read(buffer_,
                                  beast::bind_front_handler(&WebSocketSession::on_read,
                                                            derived().shared_from_this()));
    }

    void do_write(){
        std::unique_lock<std::mutex> l(mtx_);
        if(q_state != SENDING && !q_.empty()){
            q_state = SENDING;
            derived().ws().async_write(net::buffer(q_.front()),
                                       beast::bind_front_handler(&WebSocketSession::on_write,
                                                                 derived().shared_from_this()));
        }
    }

    void send_buff(const std::string &d){
        std::unique_lock<std::mutex> l(mtx_);
        q_.push_back(d);
        l.unlock();
        do_write();
    }

    // Implementation of "firmware_update" command
    int impl_firmware_update(const json_rpc::JsonRpc &jrpc){
        using namespace gdt_grpc;
        // get params
        auto &j_params = jrpc.get_params();
        // get PT_FU_DATA
        auto &j_fu_data = j_params[SysagentParamMap.find(PT_FU_DATA)->second];

        // extract data
        std::string data;
        try {
            data = j_fu_data.get<std::string>();
            // create file for writing (fixed filename for security reasons)
            FILE *f = fopen("/tmp/firmware.img", "a+");
            if (!f)
                throw std::invalid_argument("error file creating file");

            // decode and write data
            const std::size_t sz = base64::decoded_size(data.size());
            std::vector<char> arr(sz);
            auto res = base64::decode(arr.data(), data.data(), data.size());
            if (fwrite(arr.data(), res.first, 1, f) != 1)
                throw std::invalid_argument("size mismatch while writing file");
            fclose(f);

        } catch (std::exception &e) {
            std::cout << e.what() << std::endl;
            return mink::error::EC_UNKNOWN;
        }
        // ok
        return 0;
    }


    void on_read(beast::error_code ec, std::size_t bt){
        boost::ignore_unused(bt);

        // This indicates that the websocket_session was closed
        if (ec == websocket::error::closed)
            return;

        if (ec)
            return fail(ec, "WebSocketSession::read");

        // accept only text data
        if (!derived().ws().got_text()){
            // close ws session (code 1000)
            derived().ws().async_close({websocket::close_code::normal},
                                       [](beast::error_code) {});
            return;
        }

        // parse
        std::string rpc_data(net::buffers_begin(buffer_.data()),
                             net::buffers_end(buffer_.data()));
        json j = json::parse(rpc_data, nullptr, false);

        // text reply
        derived().ws().text(true);
        // clear buffer
        buffer_.consume(buffer_.size());
        // reply data
        std::string ws_rpl;

        // validate json
        if (j.is_discarded()){
            ws_rpl = Jrpc::gen_err(mink::error::EC_JSON_MALFORMED).dump();
            //sz = net::buffer_copy(buffer_.prepare(ws_rpl.size()),
            //                      net::buffer(ws_rpl));
            send_buff(ws_rpl);
            mink::CURRENT_DAEMON->log(mink::LLT_DEBUG,
                                      "JSON RPC malformed = %s",
                                      rpc_data.c_str());
            reading_.store(false);
            do_read();
            return;

        }else{
            // create json rpc parser
            Jrpc jrpc(j);
            // request id
            int id = 0;
            // request timeout
            int req_tmt = 2000;
            // daemon
            auto dd = static_cast<JsonRpcdDescriptor*>(mink::CURRENT_DAEMON);
            // verify if json is a valid json rpc data
            try {
                jrpc.verify(true);
                mink::CURRENT_DAEMON->log(mink::LLT_DEBUG,
                                          "JSON RPC received = %s",
                                          j.dump().c_str());
                id = jrpc.get_id();
                req_tmt = jrpc.get_mink_timeout();
                // check if method is supported
                if(jrpc.get_method_id() > -1){
                    // auth check
                    if (!auth_done()) {
                        // check method
                        if (jrpc.get_method_id() != gdt_grpc::CMD_AUTH)
                            throw AuthException(mink::error::EC_AUTH_INVALID_METHOD);

                        // check credentials
                        const std::string &crdts = jrpc.get_auth_crdts();

                        // user auth info
                        std::tuple<int, std::string, std::string, int, int> ua;
                        // connect with DB
                        ua = user_auth_jrpc(crdts);

                        /**************************************/
                        /* tuple index [3] = user auth status */
                        /**************************************/
                        // -1 = invalid user
                        //  0 = user found, invalid password
                        //  1 = user found and authenticated
                        if (std::get<3>(ua) == -1)
                            throw AuthException(mink::error::EC_AUTH_UNKNOWN_USER);

                        /**************/
                        /* user found */
                        /**************/
                        // get unix timestamp (part of user tuple)
                        auto ts_now = stdc::system_clock::now().time_since_epoch();
                        // now ts msec
                        uint64_t now_msec = stdc::duration_cast<stdc::milliseconds>(ts_now).count();

                        // invalid password check
                        if (std::get<3>(ua) == 0){
                            // find user
                            UserBanInfo *bi = USERS.get_banned(std::get<1>(ua));

                            // add to list if not found
                            if (!bi)
                                bi = USERS.add_attempt(std::get<1>(ua));

                            // if found, inc attempts
                            else
                                ++bi->attemtps;

                            // check if banned
                            if (bi->banned){
                                // check if ban can be lifted
                                if(now_msec - bi->ts_msec > bi->ts_banned_until){
                                    USERS.lift_ban(bi->username);
                                    bi = nullptr;

                                }else{
                                    // too many failed attempts
                                    throw AuthException(mink::error::EC_AUTH_USER_BANNED);
                                }

                            // check if ban needs to be set
                            }else{
                                if(bi->attemtps >= dd->dparams.get_pval<int>(6)){
                                    bi->banned = true;
                                    bi->ts_banned_until = now_msec + (dd->dparams.get_pval<int>(7) * 60 * 1000);
                                    // user is now banned
                                    throw AuthException(mink::error::EC_AUTH_USER_BANNED);
                                }
                            }

                            // invalid password
                            throw AuthException(mink::error::EC_AUTH_FAILED);

                        // password ok, check if user was banned
                        }else{
                            // find
                            UserBanInfo *bi = USERS.get_banned(std::get<1>(ua));
                            // user found, check if ban can be lifted
                            if(bi && bi->banned){
                                if(bi->ts_banned_until <= now_msec){
                                    USERS.lift_ban(bi->username);

                                // ban can't be lifted just yet
                                }else{
                                    throw AuthException(mink::error::EC_AUTH_USER_BANNED);
                                }
                            }
                        }

#ifdef ENABLE_WS_SINGLE_SESSION
                        if (USERS.count() > 0) {
                            // new user is admin, logout other users
                            if (std::get<4>(ua) == 1) {
                                // logout other users
                                USERS.process_all([this](const usr_info_t &u) {
                                    WebSocketBase *ws = std::get<2>(u);
                                    if (ws != this) ws->do_close();
                                });
                                USERS.remove_all();

                            // new user is a "regular" user
                            }else{
                                // check if admin user is logged in
                                bool al = false;
                                USERS.process_all([&al](const usr_info_t &u) {
                                    int f = std::get<1>(u);
                                    if (f == 1)
                                        al = true;
                                });

                                // admin already logged in, close connection
                                if (al){
                                    do_close();
                                    return;

                                // other "regular"users found, disconnect them
                                }else{
                                    USERS.process_all([this](const usr_info_t &u) {
                                        WebSocketBase *ws = std::get<2>(u);
                                        if (ws != this) ws->do_close();
                                    });
                                    USERS.remove_all();
                                }
                            }
                        }
#endif


                        // save session credentials
                        set_credentials(std::get<0>(ua),
                                        std::get<1>(ua),
                                        std::get<2>(ua),
                                        std::get<4>(ua));

                        // add to user list
                        auto new_usr = std::make_tuple(std::get<1>(ua),
                                                       std::get<4>(ua),
                                                       this,
                                                       now_msec);
                        USERS.add(new_usr);

                        // set current user for this connection
                        usr_info_ = new_usr;

                        // generate response
                        auto j_res = json_rpc::JsonRpc::gen_response(id);
                        j_res[json_rpc::JsonRpc::RESULT_] = json::array();
                        auto &j_res_arr = j_res.at(json_rpc::JsonRpc::RESULT_);
                        // user id
                        auto j_usr = json::object();
                        j_usr[json_rpc::JsonRpc::ID_] = std::get<0>(ua);
                        j_res_arr.push_back(j_usr);

                        // send response
                        std::string th_rpl = j_res.dump();
                        reading_.store(false);
                        send_buff(th_rpl);
                        do_read();
                        return;
                    }

                    // check for special CMD_FIRMWARE_UPDATE method
                    if (jrpc.get_method_id() == gdt_grpc::CMD_FIRMWARE_UPDATE) {
                        if (impl_firmware_update(jrpc)) {
                            ws_rpl = Jrpc::gen_err(mink::error::EC_UNKNOWN, id).dump();
                            send_buff(ws_rpl);
                        } else {
                            using namespace gdt_grpc;
                            auto j_res = json_rpc::JsonRpc::gen_response(id);
                            j_res[json_rpc::JsonRpc::RESULT_] = json::array();
                            auto &j_res_arr = j_res.at(json_rpc::JsonRpc::RESULT_);
                            // filesize
                            auto j_usr = json::object();
                            j_usr[SysagentParamMap.find(PT_FU_FSIZE)->second] = mink_utils::get_file_size("/tmp/firmware.img");
                            j_res_arr.push_back(j_usr);
                            ws_rpl = j_res.dump();
                            send_buff(ws_rpl);
                        }
                        // another read
                        reading_.store(false);
                        do_read();
                        return;
                    }

                    // tmp guid
                    uint8_t guid_b[16];
                    // push via gdt
                    if (!gdt_push(jrpc, derived().shared_from_this(), guid_b)) {
                        throw GDTException();

                    // setup timeout
                    }else{
                        std::shared_ptr<WebSocketBase> ws = derived().shared_from_this();
                        // timeout handler
                        auto self = derived().shared_from_this();
                        std::thread tt_th([ws, guid_b, id, req_tmt, self] {
                            mink_utils::Guid g;
                            g.set(guid_b);
                            // sleep
                            std::this_thread::sleep_for(std::chrono::milliseconds(req_tmt));
                            // get current guid (generated in gdt_push)
                            auto dd = static_cast<JsonRpcdDescriptor *>(mink::CURRENT_DAEMON);
                            // correlate guid
                            dd->cmap.lock();
                            JrpcPayload *pld = dd->cmap.get(g);
                            if (pld && !pld->persistent) {
                                dd->cmap.remove(g);
                                dd->cmap.unlock();
                                std::string th_rpl = Jrpc::gen_err(mink::error::EC_REQ_TIMEOUT, id).dump();
                                self->send_buff(th_rpl);
                                /*
                                // initiate another read after sending the reply
                                bool expected = true;
                                // !expected: if expected is set to true already by another thread,
                                // it's done; otherwise, try again
                                while (!self->reading_.compare_exchange_weak(expected, false) &&
                                       !expected) {}
                                // no other async reads are running, initiate one
                                self->do_read();
                                */
                                return;
                            }
                            dd->cmap.unlock();
                        });
                        tt_th.detach();

                    }
                }
            } catch (GDTException &e) {
                ws_rpl = Jrpc::gen_err(mink::error::EC_GDT_PUSH_FAILED, id).dump();
                mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                          "Cannot dispatch via GDT = %s",
                                          j.dump().c_str());

            } catch (AuthException &e) {
                ws_rpl = Jrpc::gen_err(e.get_ec(), id).dump();
                mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                          "JSON RPC authentication error [%d] = %s",
                                          e.get_ec(),
                                          j.dump().c_str());

            } catch (std::exception &e) {
                ws_rpl = Jrpc::gen_err(mink::error::EC_UNKNOWN, id).dump();
            }

            // send error reply
            if (!ws_rpl.empty()) {
                send_buff(ws_rpl);
                mink::CURRENT_DAEMON->log(mink::LLT_DEBUG,
                                          "JSON RPC error = %s",
                                          rpc_data.c_str());
                reading_.store(false);
                do_read();
                return;
            }
        }
        // another read
        reading_.store(false);
        do_read();

    }

    void on_write(beast::error_code ec, std::size_t bt){
        boost::ignore_unused(bt);

        std::unique_lock<std::mutex> l(mtx_);
        q_state = IDLE;
        q_.pop_front();
        l.unlock();

        if (ec)
            return fail(ec, "WebSocketSession::write");

        // write more
        do_write();

        // read
        do_read();

    }

    template<class Body, class Allocator>
    void run(http::request<Body, http::basic_fields<Allocator>> req){
        // Accept the WebSocket upgrade request
        do_accept(std::move(req));
    }
    bool gdt_push(const json_rpc::JsonRpc &jrpc,
                  std::shared_ptr<WebSocketBase> ws,
                  uint8_t *guid){

        auto dd = static_cast<JsonRpcdDescriptor*>(mink::CURRENT_DAEMON);
        // local routing daemon pointer
        gdt::GDTClient *gdtc = nullptr;
        // smsg
        gdt::ServiceMessage *msg = nullptr;
        // payload
        //JrpcPayload *pld = nullptr;
        // randomizer
        mink_utils::Randomizer rand;

        // *********************************************
        // ************ push via GDT *******************
        // *********************************************
        // get new router if connection broken
        if (!(dd->rtrd_gdtc && dd->rtrd_gdtc->is_registered()))
            dd->rtrd_gdtc = dd->gdts->get_registered_client("routingd");
        // local routing daemon pointer
        gdtc = dd->rtrd_gdtc;
        // null check
        if (!gdtc) {
            // TODO stats
            return false;
        }
        // allocate new service message
        msg = dd->gdtsmm->new_smsg();
        // msg sanity check
        if (!msg) {
            // TODO stats
            return false;
        }

        // service id
        msg->set_service_id(47);

        // extra params
        EVUserCB *ev_usr_cb = new EVUserCB();
        std::vector<gdt::ServiceParam*> *pmap = &ev_usr_cb->pmap;

        // mandatory params
        // ================
        // - mink service id
        // - mink command id
        // - mink destination type

        // optional params
        // ===============
        // - mink destination id

        // service id
        msg->set_service_id(jrpc.get_mink_service_id());

        // command id (method from json rpc)
        msg->vpmap.erase_param(asn1::ParameterType::_pt_mink_command_id);
        msg->vpmap.set_int(asn1::ParameterType::_pt_mink_command_id,
                           jrpc.get_method_id());
        // timeout
        msg->vpmap.set_int(asn1::ParameterType::_pt_mink_timeout,
                           jrpc.get_mink_timeout());

        // set smsg user callback as param
        msg->params.set_param(3, ev_usr_cb);

        // process params
        jrpc.process_params([msg](int id, const std::string &s) {
            // get ev_usr_cb
            EVUserCB *ev_cb = static_cast<EVUserCB *>(msg->params.get_param(3));

            // OCTETS or STRING
            if(s.size() > msg->vpmap.get_max()) {
                gdt::ServiceParam *sp = msg->get_smsg_manager()
                                           ->get_param_factory()
                                           ->new_param(gdt::SPT_OCTETS);
                if (sp) {
                    ev_cb->buff.push_back(s);
                    const auto &lv = ev_cb->buff.back();
                    sp->set_data(lv.data(), lv.size());
                    sp->set_id(id);
                    sp->set_index(0);
                    sp->set_extra_type(0);
                    ev_cb->pmap.push_back(sp);
                }

            }else{
                // set gdt data
                msg->vpmap.set_cstr(id, s.c_str());
            }
            return true;
        });

        // set source daemon type
        msg->vpmap.set_cstr(asn1::ParameterType::_pt_mink_daemon_type,
                            dd->get_daemon_type());
        // set source daemon id
        msg->vpmap.set_cstr(asn1::ParameterType::_pt_mink_daemon_id,
                            dd->get_daemon_id());

        // set credentials
        msg->vpmap.set_cstr(asn1::ParameterType::_pt_mink_auth_id,
                            usr_.c_str());
        msg->vpmap.set_cstr(asn1::ParameterType::_pt_mink_auth_password,
                            pwd_.c_str());

        // create payload object for correlation (grpc <-> gdt)
        JrpcPayload pld;
        // set correlation payload data
        pld.cdata = ws;
        pld.id = jrpc.get_id();
        // generate guid
        rand.generate(guid, 16);
        pld.guid.set(guid);
        pld.ts = std::chrono::system_clock::now();
        msg->vpmap.set_octets(asn1::ParameterType::_pt_mink_guid,
                              pld.guid.data(),
                              16);
        // sync vpmap
        if (dd->gdtsmm->vpmap_sparam_sync(msg, pmap) != 0) {
            // TODO stats
            dd->gdtsmm->free_smsg(msg);
            delete ev_usr_cb;
            return false;
        }

        // destination id
        const std::string *dest_id = jrpc.get_mink_did();

        // send service message
        int r = dd->gdtsmm->send(msg,
                                 gdtc,
                                 jrpc.get_mink_dtype().c_str(),
                                 (dest_id != nullptr ? dest_id->c_str() : nullptr),
                                 true,
                                 &dd->ev_srvcm_tx);
        if (r) {
            // TODO stats
            dd->gdtsmm->free_smsg(msg);
            delete ev_usr_cb;
            return false;
        }

        // save to correlarion map
        dd->cmap.lock();
        dd->cmap.set(pld.guid, pld);
        dd->cmap.unlock();

        return true;

    }
    void set_credentials(const int usr_id,
                         const std::string &usr,
                         const std::string &pwd,
                         const int usr_flags){
        usr_id_ = usr_id;
        usr_.assign(usr);
        pwd_.assign(pwd);
        usr_flags_ = usr_flags;
        auth_ts = std::chrono::system_clock::now();

    }
    bool auth_done(){
        return (auth_ts.time_since_epoch().count() > 0);
    }

    beast::flat_buffer &get_buffer() {
        return buffer_;
    }

    std::mutex &get_mtx(){
        return mtx_;
    }

    void async_buffer_send(const std::string &d) {
        std::unique_lock<std::mutex> l(mtx_);
        q_.push_back(std::move(d));
        l.unlock();
        do_write();
    }

    void do_close(){
        // Send a TCP shutdown
        beast::error_code ec;
        beast::get_lowest_layer(derived().ws()).socket().shutdown(tcp::socket::shutdown_send, ec);
    }

private:
    beast::flat_buffer buffer_;
    int usr_id_;
    std::string usr_;
    std::string pwd_;
    std::chrono::time_point<std::chrono::system_clock> auth_ts;
    int usr_flags_;
    enum QState { IDLE, SENDING } q_state = IDLE;
    std::atomic_bool reading_;
    std::deque<std::string> q_;
    std::mutex mtx_;
};

/*************************/
/* SSL WebSocket Session */
/*************************/
class SSLWebSocketSession
    : public WebSocketSession<SSLWebSocketSession>
    , public std::enable_shared_from_this<SSLWebSocketSession> {
public:
    // Create SSL websocket session
    explicit SSLWebSocketSession(beast::ssl_stream<beast::tcp_stream> &&stream);

    // Called by the base class
    websocket::stream<beast::ssl_stream<beast::tcp_stream>> &ws();

private:
    websocket::stream<beast::ssl_stream<beast::tcp_stream>> ws_;

};

/*******************/
/* Plain WebSocket */
/*******************/
class PlainWebSocketSession
    : public WebSocketSession<PlainWebSocketSession>
    , public std::enable_shared_from_this<PlainWebSocketSession> {
public:
    // Create plain websocket session
    explicit PlainWebSocketSession(beast::tcp_stream &&stream);

    // Called by the base class
    websocket::stream<beast::tcp_stream> &ws();

private:
    websocket::stream<beast::tcp_stream> ws_;
};

/*******************************************/
/* Create SSL or TCP stream based sessions */
/*******************************************/
#ifdef ENABLE_PLAIN_WS
template <class Body, class Allocator>
void make_websocket_session(beast::tcp_stream stream,
                            http::request<Body, http::basic_fields<Allocator>> req){
    std::make_shared<PlainWebSocketSession>(std::move(stream))->run(std::move(req));
}
#endif

template <class Body, class Allocator>
void make_websocket_session(beast::ssl_stream<beast::tcp_stream> stream,
                            http::request<Body, http::basic_fields<Allocator>> req){
    std::make_shared<SSLWebSocketSession>(std::move(stream))->run(std::move(req));
}



/**********************/
/* HTTP/HTTPS Session */
/**********************/
template <class Derived>
class HttpSession {
public:
    explicit HttpSession(beast::flat_buffer buffer,
                         std::shared_ptr<std::string const> const &droot)
        : droot_(droot)
        , buffer_(std::move(buffer)) {}

    HttpSession(const HttpSession &o) = delete;
    ~HttpSession() = default;
    const HttpSession &operator=(const HttpSession &o) = delete;

    // Access the derived class
    Derived &derived(){
         return static_cast<Derived &>(*this);
    }
    void do_read(){
        // Construct a new parser for each message
        parser_.emplace();

        // Apply a reasonable limit to the allowed size
        // of the body in bytes to prevent abuse.
        parser_->body_limit(10000);

        // Set the timeout
        beast::get_lowest_layer(derived().stream()).expires_after(std::chrono::seconds(30));

        // Read a request using the parser-oriented interface
        http::async_read(derived().stream(),
                         buffer_,
                         *parser_,
                         beast::bind_front_handler(&HttpSession::on_read,
                                                   derived().shared_from_this()));
    }
    void on_read(beast::error_code ec, std::size_t bt){
        boost::ignore_unused(bt);

        // This means they closed the connection
        if (ec == http::error::end_of_stream)
            return derived().do_eof();

        if (ec)
            return fail(ec, "http::read");

        // See if it is a WebSocket Upgrade
        if (websocket::is_upgrade(parser_->get())) {
            // The websocket::stream uses its own timeout settings.
            beast::get_lowest_layer(derived().stream()).expires_never();
            // auth
            /*
            auto req = parser_->get();
            boost::string_view auth_hdr = req[http::field::authorization];
            boost::string_view req_m = req.target();

            // user auth info
            std::tuple<std::string, std::string, bool, int> ua;
            // Header
            if(!auth_hdr.empty()){
                if (!user_auth_prepare(auth_hdr, 0)){
                    mink::CURRENT_DAEMON->log(mink::LLT_DEBUG,
                                              "Invalid authentication format: [Header]");
                    return derived().do_eof();
                }

                // connect with DB
                ua = user_auth(auth_hdr);
                if (!std::get<2>(ua)){
                    mink::CURRENT_DAEMON->log(mink::LLT_DEBUG,
                                              "Invalid user credentials");
                    return derived().do_eof();
                }

            }
            */
            /*************************/
            /* Handover to WebSocket */
            /*************************/
            // Create a websocket session, transferring ownership
            // of both the socket and the HTTP request.
            return make_websocket_session(derived().release_stream(),
                                          parser_->release());

        }
        // ws/wss only
        return derived().do_eof();

    }

    void on_write(bool close, beast::error_code ec, std::size_t bt){
        boost::ignore_unused(bt);

        if (ec)
            return fail(ec, "http::write");

        if (close) {
            // This means we should close the connection, usually because
            // the response indicated the "Connection: close" semantic.
            return derived().do_eof();
        }
        // read another request
        do_read();
    }
protected:
    beast::flat_buffer buffer_;

private:
    std::shared_ptr<std::string const> droot_;
    boost::optional<http::request_parser<http::string_body>> parser_;
};

#ifdef ENABLE_PLAIN_WS
/**********************/
/* Plain HTTP Session */
/**********************/
class PlainHttpSession
    : public HttpSession<PlainHttpSession>
    , public std::enable_shared_from_this<PlainHttpSession> {
public:
    explicit PlainHttpSession(beast::tcp_stream &&stream,
                              beast::flat_buffer &&buffer,
                              std::shared_ptr<std::string const> const &droot);

    void run();
    beast::tcp_stream &stream();
    beast::tcp_stream release_stream();
    void do_eof();

private:
    beast::tcp_stream stream_;
};
#endif

/********************/
/* SSL HTTP Session */
/********************/
class SSLHTTPSesssion
    : public HttpSession<SSLHTTPSesssion>
    , public std::enable_shared_from_this<SSLHTTPSesssion> {
public:
    explicit SSLHTTPSesssion(beast::tcp_stream &&stream,
                             ssl::context &ctx,
                             beast::flat_buffer &&buffer,
                             std::shared_ptr<std::string const> const &droot);

    void run();
    beast::ssl_stream<beast::tcp_stream> &stream();
    beast::ssl_stream<beast::tcp_stream> release_stream();
    void do_eof();
    void on_handshake(beast::error_code ec, std::size_t bt);
    void on_shutdown(beast::error_code ec);

private:
    beast::ssl_stream<beast::tcp_stream> stream_;
};

/******************/
/* Detect Session */
/******************/
class DetectSession : public std::enable_shared_from_this<DetectSession> {
public:
    explicit DetectSession(tcp::socket &&socket,
                           ssl::context &ctx,
                           std::shared_ptr<std::string const> const &droot);
    DetectSession(const DetectSession &o) = delete;
    ~DetectSession() = default;

    void run();
    void on_run();
    void on_detect(beast::error_code ec, bool result);


private:
    beast::tcp_stream stream_;
    ssl::context &ctx_;
    std::shared_ptr<std::string const> droot_;
    beast::flat_buffer buffer_;
};

/***********************/
/* Connection listener */
/***********************/
class Listener : public std::enable_shared_from_this<Listener> {
public:
    Listener(net::io_context &ioc,
             ssl::context &ctx,
             tcp::endpoint endpoint,
             std::shared_ptr<std::string const> const &droot);
    Listener(const Listener &o) = delete;
    ~Listener() = default;
    const Listener &operator=(const Listener &o) = delete;

    void run();

private:
    void do_accept();
    void on_accept(beast::error_code ec, tcp::socket socket);

    net::io_context &ioc_;
    ssl::context &ctx_;
    tcp::acceptor acceptor_;
    std::shared_ptr<std::string const> droot_;
    bool single_session = false;
};

#endif /* ifndef MINK_WS_SERVER_H */
