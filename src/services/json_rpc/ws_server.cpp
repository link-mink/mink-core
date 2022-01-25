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
#include "ws_server.h"
#include <boost/algorithm/string/trim.hpp>
#include <boost/range/as_array.hpp>
#include <gdt.pb.enums_only.h>
#include <chrono>

void fail(beast::error_code ec, char const *what) {
    if (ec == net::ssl::error::stream_truncated)
        return;
    std::cerr << what << ": " << ec.message() << "\n";
}

/************/
/* UserList */
/************/
usr_info_t UserList::exists(const std::string &u){
    std::unique_lock<std::mutex> lock(m);
    for (auto it = users.cbegin(); it != users.cend(); ++it) {
        if(std::get<0>(*it) == u) return *it;
    }
    return std::make_tuple("", 0, nullptr, 0);
}

UserBanInfo *UserList::add_attempt(const std::string &u){
    std::unique_lock<std::mutex> lock(m);
    auto it = ban_lst.find(u);
    // add new user
    if(it == ban_lst.end()){
        // get unix timestamp (part of user tuple)
        auto ts_now = stdc::system_clock::now().time_since_epoch();
        uint64_t ts_msec = stdc::duration_cast<stdc::milliseconds>(ts_now).count();
        ban_lst.emplace(u, UserBanInfo{u, 1, ts_msec, false});

    // user exists
    } else {
        ++it->second.attemtps;
    }
    return &ban_lst.find(u)->second;
}

UserBanInfo *UserList::get_banned(const std::string &u){
    std::unique_lock<std::mutex> lock(m);
    auto it = ban_lst.find(u);
    if(it != ban_lst.end()){
        m.unlock();
        return &it->second;
    }
    return nullptr;
}

void UserList::lift_ban(const std::string &u){
    std::unique_lock<std::mutex> lock(m);
    ban_lst.erase(u);
}

bool UserList::add(const usr_info_t &u){
    std::unique_lock<std::mutex> lock(m);
    users.push_back(u);
    return true;
}

void UserList::remove(const std::string &u, const uint64_t &ts){
    std::unique_lock<std::mutex> lock(m);
    for (auto it = users.begin(); it != users.end();) {
        // match username
        if (std::get<0>(*it) == u && std::get<3>(*it) == ts) {
            it = users.erase(it);

        } else {
            ++it;
        }
    }
}

void UserList::remove_all(){
    std::unique_lock<std::mutex> lock(m);
    users.clear();
}

void UserList::process_all(const std::function<void(const usr_info_t &)> &f) {
    std::unique_lock<std::mutex> lock(m);
    std::all_of(users.cbegin(), users.cend(), [f](const usr_info_t &u) {
        f(u);
        return true;
    });
}

std::size_t UserList::count(){
    std::unique_lock<std::mutex> lock(m);
    return users.size();
}

// static list of users
UserList USERS;

/*************************/
/* SSL WebSocket Session */
/*************************/
SSLWebSocketSession::SSLWebSocketSession(beast::ssl_stream<beast::tcp_stream> &&stream)
    : ws_(std::move(stream)) {}

websocket::stream<beast::ssl_stream<beast::tcp_stream>> &SSLWebSocketSession::ws() {
    return ws_;
}

#ifdef ENABLE_PLAIN_WS
/*******************/
/* Plain WebSocket */
/*******************/
PlainWebSocketSession::PlainWebSocketSession(beast::tcp_stream &&stream)
    : ws_(std::move(stream)) {}

websocket::stream<beast::tcp_stream> &PlainWebSocketSession::ws() {
    return ws_;
}

/**********************/
/* Plain HTTP Session */
/**********************/
PlainHttpSession::PlainHttpSession(beast::tcp_stream &&stream,
                                   beast::flat_buffer &&buffer,
                                   std::shared_ptr<std::string const> const &droot)
    : HttpSession<PlainHttpSession>(std::move(buffer), droot)
    , stream_(std::move(stream)) {}

void PlainHttpSession::run(){
    this->do_read();
}

beast::tcp_stream &PlainHttpSession::stream(){
    return stream_;
}

beast::tcp_stream PlainHttpSession::release_stream(){
    return std::move(stream_);
}

void PlainHttpSession::do_eof(){
    // Send a TCP shutdown
    beast::error_code ec;
    stream_.socket().shutdown(tcp::socket::shutdown_send, ec);

    // At this point the connection is closed gracefully
}
#endif

/********************/
/* SSL HTTP Session */
/********************/
SSLHTTPSesssion::SSLHTTPSesssion(beast::tcp_stream &&stream,
                                 ssl::context &ctx,
                                 beast::flat_buffer &&buffer,
                                 std::shared_ptr<std::string const> const &droot)
    : HttpSession<SSLHTTPSesssion>(std::move(buffer), droot)
    , stream_(std::move(stream), ctx) {}

void SSLHTTPSesssion::run(){
    // Set the timeout
    beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));

    // Perform the SSL handshake
    // Note, this is the buffered version of the handshake.
    stream_.async_handshake(ssl::stream_base::server, 
                            buffer_.data(),
                            beast::bind_front_handler(&SSLHTTPSesssion::on_handshake,
                                                      shared_from_this()));
}

beast::ssl_stream<beast::tcp_stream> &SSLHTTPSesssion::stream(){
    return stream_;
}

beast::ssl_stream<beast::tcp_stream> SSLHTTPSesssion::release_stream(){
    return std::move(stream_);
}

void SSLHTTPSesssion::do_eof(){
    // Set the timeout
    beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));

    // Perform the SSL shutdown
    stream_.async_shutdown(beast::bind_front_handler(&SSLHTTPSesssion::on_shutdown, 
                                                     shared_from_this()));
}

void SSLHTTPSesssion::on_handshake(beast::error_code ec, std::size_t bt){
    if (ec)
        return fail(ec, "SSLHTTPSesssion::handshake");

    // Consume the portion of the buffer used by the handshake
    buffer_.consume(bt);

    do_read();
}

void SSLHTTPSesssion::on_shutdown(beast::error_code ec){
    if (ec)
        return fail(ec, "SSLHTTPSesssion::shutdown");

    // At this point the connection is closed gracefully
}


std::tuple<int, std::string, std::string, int, int> user_auth_jrpc(const std::string &crdt){
    // extract user and pwd hash 
    std::string user;
    std::string pwd;

    // split header
    for (auto it = crdt.cbegin(); it != crdt.cend(); ++it) {
        if (*it == ':') {
            // username
            user.assign(crdt.cbegin(), it);
            // skip ':'
            ++it;
            // sanity check
            if (it == crdt.cend())
                return std::make_tuple(-1, "", "", false, 0);
            // pwd hash
            pwd.assign(it, crdt.cend());
        }
    }
    // pwd sanity check
    if (pwd.size() < 6)
        return std::make_tuple(-1, "", "", false, 0);

    // find user in db and auth
    auto dd = static_cast<JsonRpcdDescriptor*>(mink::CURRENT_DAEMON);
    // get credentials
    auto c = dd->dbm.user_auth(user, pwd);
    // return credentials
    return std::make_tuple(std::get<1>(c),
                           user, 
                           pwd,
                           std::get<0>(c),
                           std::get<2>(c));
}

bool user_auth_prepare(boost::string_view &auth_str, int type){
    // Header
    if(type == 0){
        // check for "Basic"
        std::string::size_type n = auth_str.find("Basic");
        if (n == std::string::npos)
            return false;

        // skip "Basic "
        auth_str.remove_prefix(6);
        // sanity check
        if (auth_str.size() < 10)
            return false;

    // URL param
    }else if(type == 1){
        // check for "/?auth="
        std::string::size_type n = auth_str.find("/?auth=");
        if (n == std::string::npos)
            return false;

        // skip "/?auth="
        auth_str.remove_prefix(7);
        // sanity check
        if (auth_str.size() < 10)
            return false;

    // unknown
    } else
        return false;

    // token found
    return true;
}


/*
std::tuple<std::string, std::string, bool, int> user_auth(boost::string_view &auth_hdr){
    // decode base64
    const std::size_t sz = base64::decoded_size(auth_hdr.size());
    std::vector<char> arr(sz);
    base64::decode(arr.data(), auth_hdr.data(), auth_hdr.size());

    // extract user and pwd hash 
    std::string user;
    std::string pwd;

    // split header
    for (auto it = arr.cbegin(); it != arr.cend(); ++it) {
        if (*it == ':') {
            // username
            user.assign(arr.cbegin(), it);
            // skip ':'
            ++it;
            // sanity check
            if (it == arr.cend())
                return std::make_tuple("", "", false, 0);
            // pwd hash
            pwd.assign(it, arr.cend());
            boost::trim_right_if(pwd, boost::is_any_of(boost::as_array("\x0d\x0a\x00")));
        }
    }
    // pwd sanity check
    if (pwd.size() < 6)
        return std::make_tuple("", "", false, 0);

    // find user in db and auth
    auto dd = static_cast<JsonRpcdDescriptor*>(mink::CURRENT_DAEMON);
    // get credentials
    auto c = dd->dbm.user_auth(user, pwd);
    // return credentials
    return std::make_tuple(user, pwd, c.first, c.second);
}
*/

/*****************/
/* DetectSession */
/*****************/
DetectSession::DetectSession(tcp::socket &&socket,
                             ssl::context &ctx,
                             std::shared_ptr<std::string const> const &droot) 
    : stream_(std::move(socket))
    , ctx_(ctx)
    , droot_(droot) {}

void DetectSession::run() {
    net::dispatch(stream_.get_executor(),
                  beast::bind_front_handler(&DetectSession::on_run,
                                            this->shared_from_this()));
}

void DetectSession::on_run() {
    // Set the timeout.
    stream_.expires_after(std::chrono::seconds(30));

    beast::async_detect_ssl(stream_, 
                            buffer_,
                            beast::bind_front_handler(&DetectSession::on_detect,
                                                      this->shared_from_this()));
}

void DetectSession::on_detect(beast::error_code ec, bool result) {
    if (ec)
        return fail(ec, "session::on_detect");

    if (result) {
        // Launch HTTPS session
        std::make_shared<SSLHTTPSesssion>(std::move(stream_), 
                                          ctx_,
                                          std::move(buffer_), 
                                          droot_)->run();
        return;
    }
#ifdef ENABLE_PLAIN_WS 
    // Launch HTTP session  
    std::make_shared<PlainHttpSession>(std::move(stream_), 
                                       std::move(buffer_), 
                                       droot_)->run();
#endif

}




/***********************/
/* Connection listener */
/***********************/
Listener::Listener(net::io_context &ioc, 
                   ssl::context &ctx,
                   tcp::endpoint endpoint,
                   std::shared_ptr<std::string const> const &droot) : ioc_(ioc), 
                                                                      ctx_(ctx),
                                                                      acceptor_(ioc),
                                                                      droot_(droot) {
                                                                    
    beast::error_code ec;

    // Open the acceptor
    acceptor_.open(endpoint.protocol(), ec);
    if (ec) {
        fail(ec, "listener::open");
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR, 
                                 "cannot create TCP socket, shutting down...", 
                                  endpoint.port());
        exit(EXIT_FAILURE);
    }

    // Allow address reuse
    acceptor_.set_option(net::socket_base::reuse_address(true), ec);
    if (ec) {
        fail(ec, "listener::set_option");
        return;
    }

    // Bind to the server address
    acceptor_.bind(endpoint, ec);
    if (ec) {
        fail(ec, "listener::bind");
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR, 
                                 "cannot bind listener to port [%d], shutting down...", 
                                  endpoint.port());
        exit(EXIT_FAILURE);
    }

    // Start listening for connections
    acceptor_.listen(net::socket_base::max_listen_connections, ec);
    if (ec) {
        fail(ec, "listener::listen");
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR, 
                                 "cannot initiate listener on port [%d], shutting down...", 
                                  endpoint.port());
        exit(EXIT_FAILURE);
    }
}


// start accepting connections
void Listener::run(){
    net::dispatch(acceptor_.get_executor(),
                  beast::bind_front_handler(&Listener::do_accept,
                                            this->shared_from_this()));

}

void Listener::do_accept(){
    // The new connection gets its own strand
    acceptor_.async_accept(net::make_strand(ioc_),
                           beast::bind_front_handler(&Listener::on_accept, 
                                                     shared_from_this()));
}

void Listener::on_accept(beast::error_code ec, tcp::socket socket){
    if (ec) {
        fail(ec, "listener::on_accept");
    } else {
        // Create the session and run it
        std::make_shared<DetectSession>(std::move(socket), 
                                        ctx_, 
                                        droot_)->run();
    }

    // Accept another connection
    do_accept();
}

