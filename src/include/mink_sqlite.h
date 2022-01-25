/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef MINK_SQLITE_H
#define MINK_SQLITE_H 

#include <sqlite3.h>
#include <string>
#include <mink_utils.h>

namespace mink_db {
    // vpmap alias
    using vpmap = mink_utils::PooledVPMap<uint32_t>;

    // sqlite query type
    enum class QueryType {
        USER_AUTH = 0,
        USER_ADD,
        USER_DEL,
        USER_CMD_DEL,
        USER_CMD_AUTH,
        USER_CMD_SPECIFIC_AUTH
    };

    // Command specific auth base class
    class CmdSpecificAuth {
    public:
        CmdSpecificAuth() = default;
        virtual ~CmdSpecificAuth() = default;
        CmdSpecificAuth(const CmdSpecificAuth &o) = delete;
        CmdSpecificAuth &operator=(const CmdSpecificAuth &o) = delete;
        // cmd handlers implemented in derived classes
        virtual bool do_auth(sqlite3 *db, const vpmap &vp) = 0;
    };

    // CMD_UBUS_CALL (7) cmd specific auth class
    class CmdUbusAuth : public CmdSpecificAuth {
    public:
        bool do_auth(sqlite3 *db, const vpmap &vp);
    };

    // sqlite manager
    class SqliteManager {
    public:
        SqliteManager();
        explicit SqliteManager(const std::string &db_f);
        ~SqliteManager();
        SqliteManager(const SqliteManager &o) = delete;
        SqliteManager &operator=(const SqliteManager &o) = delete;

        bool cmd_auth(const int cmd_id, const std::string &u);
        bool cmd_specific_auth(const vpmap &vp, const std::string &u);
        std::tuple<int, int, int> user_auth(const std::string &u, const std::string &p);
        void connect(const std::string &db_f);

        // static constants
        static const char *SQL_USER_AUTH;
        static const char *SQL_USER_ADD;
        static const char *SQL_USER_DEL;
        static const char *SQL_USER_CMD_DEL;
        static const char *SQL_USER_CMD_AUTH;
        static const char *SQL_USER_CMD_SPECIFIC_AUTH;

    private:
        void create_cmd_spec_hndlrs();

        sqlite3 *db = nullptr;
        std::map<int, CmdSpecificAuth *> cmd_spec_auth_map;
    };
}

#endif /* ifndef MINK_SQLITE_H */
