/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <mink_sqlite.h>
#include <iostream>
#include <string.h>
#include <string.h>
#include <gdt.pb.enums_only.h>
#include <algorithm>
#include <gdt_def.h>

// aliases
using msqlm = mink_db::SqliteManager;
using vparam = mink_utils::VariantParam;
using ptype = asn1::ParameterType;

/******************/
/* sql statements */
/******************/
// authenticate user
const char *msqlm::SQL_USER_AUTH =
    "SELECT a.id, "
    "       a.flags, "
    "       a.username, "
    "       iif(b.username is NULL, 0, 1) as auth "
    "FROM user a "
    "LEFT JOIN "
    "   (SELECT flags, username  "
    "    FROM user a "
    "    WHERE username = ? AND "
    "    password = ?) b "
    "ON a.username = b.username "
    "WHERE a.username = ?";

// get user
const char *msqlm::SQL_USER_GET =
    "SELECT * FROM user "
    "WHERE username = ?";

// add new user
const char *msqlm::SQL_USER_ADD =
    "INSERT INTO user(username, password) "
    "VALUES(?, ?)";

// delete user
const char *msqlm::SQL_USER_DEL =
    "DELETE FROM user "
    "WHERE username = ?";

// delete user <-> cmd relation
const char *msqlm::SQL_USER_CMD_DEL =
    "DELETE FROM user_action "
    "WHERE user_id = ?";

// authenticate user action
const char *msqlm::SQL_USER_CMD_AUTH =
    "SELECT b.id "
    "FROM user_action a, user b "
    "WHERE a.user_id = b.id AND "
    "a.cmd_id = ? AND "
    "b.username = ?";

// authenticate action specific methods
const char *msqlm::SQL_USER_CMD_SPECIFIC_AUTH =
    "SELECT c.args "
    "FROM user_action_specific a, user b, action_specific c "
    "WHERE a.user_id = b.id AND "
    "b.username = ? AND "
    "c.cmd_id = ?";


/***************/
/* CmdUbusAuth */
/***************/
bool mink_db::CmdUbusAuth::do_auth(sqlite3 *db, const vpmap &vp){
    if (!db)
        throw std::invalid_argument("invalid db connection");

     // look for cmd id
    const vparam *vp_cmd_id = vp.get_param(ptype::_pt_mink_command_id);
    if (!vp_cmd_id)
        return false;

    // look for username
    const vparam *vp_usr = vp.get_param(ptype::_pt_mink_auth_id);
    if (!vp_usr)
        return false;

    // look for ubus path
    const vparam *vp_upath = vp.get_param(gdt_grpc::PT_OWRT_UBUS_PATH);
    if (!vp_upath)
        return false;

     // look for ubus method
    const vparam *vp_umethod = vp.get_param(gdt_grpc::PT_OWRT_UBUS_METHOD);
    if (!vp_umethod)
        return false;

    // command id and username
    int cmd_id = static_cast<int>(*vp_cmd_id);
    std::string usr(static_cast<char *>(*vp_usr));

    // ubus path and meethod from request
    std::string req_upath(static_cast<char *>(*vp_upath));
    std::string req_umethod(static_cast<char *>(*vp_umethod));

    // prepare statement
    sqlite3_stmt *stmt = nullptr;
    int r = sqlite3_prepare_v2(db,
                               msqlm::SQL_USER_CMD_SPECIFIC_AUTH,
                               -1,
                               &stmt,
                               nullptr);
    if (r != SQLITE_OK)
        throw std::invalid_argument("sql:cannot prepare statement");

    // username
    if (sqlite3_bind_text(stmt, 1, usr.c_str(), usr.size(), SQLITE_STATIC))
        throw std::invalid_argument("sql:cannot bind username");

    // cmd id
    if (sqlite3_bind_int(stmt, 2, cmd_id))
        throw std::invalid_argument("sql:cannot bind cmd id");

    // step
    bool res = false;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        // get args
        const unsigned char *args = sqlite3_column_text(stmt, 0);
        if (!args)
            continue;

        // split args (ubus path : ubus method)
        std::string ustr(reinterpret_cast<const char *>(args));
        // check for delimiter
        std::string::size_type n = ustr.find(":");
        if (n == std::string::npos || ustr.size() <= (n + 1))
            break;
        // get ubus path from db
        std::string upath = ustr.substr(0, n);
        std::string umethod = ustr.substr(n + 1, ustr.size() - n - 1);

        // match with those from request
        if ((upath == req_upath) && (umethod == req_umethod)) {
            res = true;
            break;
        }
    }

    // cleanup
    if(sqlite3_clear_bindings(stmt))
        throw std::invalid_argument("sql:cannot clear bindings");
    if(sqlite3_reset(stmt))
        throw std::invalid_argument("sql:cannot reset statement");
    if(sqlite3_finalize(stmt))
        throw std::invalid_argument("sql:cannot finalize statement");

    // return auth res
    return res;
}

void msqlm::create_cmd_spec_hndlrs(){
    // cmd specific authorisation handlers
    cmd_spec_auth_map[gdt_grpc::CMD_UBUS_CALL] = new CmdUbusAuth();
}

/*****************/
/* SqliteManager */
/*****************/
msqlm::SqliteManager() {
    // cmd specific authorisation handlers
    create_cmd_spec_hndlrs();
}

msqlm::SqliteManager(const std::string &db_f) {
    connect(db_f);
    // cmd specific authorisation handlers
    create_cmd_spec_hndlrs();
}

msqlm::~SqliteManager(){
    if (db) sqlite3_close(db);
    std::all_of(cmd_spec_auth_map.cbegin(), cmd_spec_auth_map.cend(),
                [](const std::pair<const int, CmdSpecificAuth *> &c) {
                    delete c.second;
                    return true;
                });
}

std::tuple<int, std::string, int> msqlm::user_get(const std::string &u){
    if (!db)
        throw std::invalid_argument("invalid db connection");

    // prepare statement
    sqlite3_stmt *stmt = nullptr;
    int r = sqlite3_prepare_v2(db,
                               SQL_USER_GET,
                               -1,
                               &stmt,
                               nullptr);
    if (r != SQLITE_OK)
        throw std::invalid_argument("sql:cannot prepare statement");

    // username
    if (sqlite3_bind_text(stmt, 1, u.c_str(), u.size(), SQLITE_STATIC))
        throw std::invalid_argument("sql:cannot bind username");

    // step
    int usr_flags = 0;
    int usr_id = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        usr_id = sqlite3_column_int(stmt, 0);
        usr_flags = sqlite3_column_int(stmt, 3);
    }
    // cleanup
    if(sqlite3_clear_bindings(stmt))
        throw std::invalid_argument("sql:cannot clear bindings");
    if(sqlite3_reset(stmt))
        throw std::invalid_argument("sql:cannot reset statement");
    if(sqlite3_finalize(stmt))
        throw std::invalid_argument("sql:cannot finalize statement");

    // not found
    if (usr_id == -1) {
        throw std::invalid_argument("sql:cannot find username");
    }
    // user found
    return std::make_tuple(usr_id, u, usr_flags);
}

bool msqlm::cmd_specific_auth(const vpmap &vp, const std::string &u){
    if (!db)
        throw std::invalid_argument("invalid db connection");

     // look for cmd id
    const vparam *vp_cmd_id = vp.get_param(ptype::_pt_mink_command_id);
    if (!vp_cmd_id)
        return false;

    // check if specific cmd handler exists
    auto it = cmd_spec_auth_map.find(static_cast<int>(*vp_cmd_id));
    // handler not found, auth = success
    if (it == cmd_spec_auth_map.cend())
        return true;

    // run specific handler
    return it->second->do_auth(db, vp);
}

bool msqlm::cmd_auth(const int cmd_id, const std::string &u){
    if (!db)
        throw std::invalid_argument("invalid db connection");

    // prepare statement
    sqlite3_stmt *stmt = nullptr;
    int r = sqlite3_prepare_v2(db,
                               SQL_USER_CMD_AUTH,
                               -1,
                               &stmt,
                               nullptr);
    if (r != SQLITE_OK)
        throw std::invalid_argument("sql:cannot prepare statement");

    // cmd id
    if (sqlite3_bind_int(stmt, 1, cmd_id))
        throw std::invalid_argument("sql:cannot bind cmd id");

    // username
    if (sqlite3_bind_text(stmt, 2, u.c_str(), u.size(), SQLITE_STATIC))
        throw std::invalid_argument("sql:cannot bind username");

    // step
    bool res = false;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        res = sqlite3_data_count(stmt) > 0;

    // cleanup
    if(sqlite3_clear_bindings(stmt))
        throw std::invalid_argument("sql:cannot clear bindings");
    if(sqlite3_reset(stmt))
        throw std::invalid_argument("sql:cannot reset statement");
    if(sqlite3_finalize(stmt))
        throw std::invalid_argument("sql:cannot finalize statement");

    // default auth value
    return res;
}

std::tuple<int, int, int> msqlm::user_auth(const std::string &u, const std::string &p){
    if (!db)
        throw std::invalid_argument("invalid db connection");

    // prepare statement
    sqlite3_stmt *stmt = nullptr;
    int r = sqlite3_prepare_v2(db,
                               SQL_USER_AUTH,
                               -1,
                               &stmt,
                               nullptr);
    if (r != SQLITE_OK)
        throw std::invalid_argument("sql:cannot prepare statement");

    // username
    if (sqlite3_bind_text(stmt, 1, u.c_str(), u.size(), SQLITE_STATIC))
        throw std::invalid_argument("sql:cannot bind username");

    // pwd
    if (sqlite3_bind_text(stmt, 2, p.c_str(), p.size(), SQLITE_STATIC))
        throw std::invalid_argument("sql:cannot bind password");

    // username
    if (sqlite3_bind_text(stmt, 3, u.c_str(), u.size(), SQLITE_STATIC))
        throw std::invalid_argument("sql:cannot bind username");


    // step
    int usr_flags = 0;
    int usr_id = -1;
    int auth = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        usr_id = sqlite3_column_int(stmt, 0);
        usr_flags = sqlite3_column_int(stmt, 1);
        auth = sqlite3_column_int(stmt, 3);
    }
    // cleanup
    if(sqlite3_clear_bindings(stmt))
        throw std::invalid_argument("sql:cannot clear bindings");
    if(sqlite3_reset(stmt))
        throw std::invalid_argument("sql:cannot reset statement");
    if(sqlite3_finalize(stmt))
        throw std::invalid_argument("sql:cannot finalize statement");


    // default auth value
    return std::make_tuple(auth, usr_id, usr_flags);
}

void msqlm::connect(const std::string &db_f){
    int r = sqlite3_open_v2(db_f.c_str(),
                            &db,
                            SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX,
                            nullptr);
    if (r)
        throw std::invalid_argument("cannot open database file");

}
