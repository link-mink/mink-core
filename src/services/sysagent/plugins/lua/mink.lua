--            _       _
--  _ __ ___ (_)_ __ | | __
-- | '_ ` _ \| | '_ \| |/ /
-- | | | | | | | | | |   <
-- |_| |_| |_|_|_| |_|_|\_\
--
-- SPDX-License-Identifier: MIT
--
--

-- init module table
local mink = {}
-- set ffi
local ffi = require("ffi")
local C = ffi.C
-- mink C functions
ffi.cdef [[
    // structures
    typedef struct {
        const char *key;
        const char *value;
    } mink_cdata_column_t;

    // functions
    void free(void *p);
    void mink_lua_free_res(void *p);
    void *mink_lua_new_cmd_data();
    size_t mink_lua_cmd_data_sz(void *p);
    size_t mink_lua_cmd_data_row_sz(const int r, void *p);
    mink_cdata_column_t mink_lua_cmd_data_get_column(const int r,
                                                     const int c,
                                                     void *p);
    int mink_lua_cmd_call(void *md,
                          int argc,
                          const char **args,
                          void *out);
]]

-- ************
-- * wrappers *
-- ************
local function w_mink_lua_cmd_call(cmd)
    -- array length
    local l = #cmd
    -- create C char array
    local c_array = ffi.new("const char *[?]", #cmd)
    -- copy values
    for i = 1, l do
        c_array[i - 1] = cmd[i]
    end
    -- create output buffer
    local c_data = C.mink_lua_new_cmd_data()
    -- call C method
    local res = C.mink_lua_cmd_call(mink.args[1],
                                    l,
                                    c_array,
                                    c_data)
    -- if successful, copy C data to lua table
    if res == 0 then
        -- result
        local res = {}
        -- cmd data size
        local sz = tonumber(C.mink_lua_cmd_data_sz(c_data))
        -- loop result data (rows)
        for i = 0, sz - 1 do
            -- create table row
            res[i + 1] = {}
            -- get column count
            local sz_c = tonumber(C.mink_lua_cmd_data_row_sz(i, c_data))
            -- loop columns
            for j = 0, sz_c - 1 do
                -- get column key/value
                local c = C.mink_lua_cmd_data_get_column(i, j, c_data)
                -- add column to lua table
                if c.value ~= nil then
                    local k = 1
                    -- update key, if not null
                    if c.key ~= nil and string.len(ffi.string(c.key)) > 0 then
                        k = ffi.string(c.key)
                    end
                    -- add column
                    res[i + 1][k] = ffi.string(c.value)
                end
            end
        end
        -- free C plugin data
        C.mink_lua_free_res(c_data)
        -- return lua table
        return res
    end
    -- free C plugin data
    C.mink_lua_free_res(c_data)
end

-- **************************
-- *** module init method ***
-- **************************
local function init(...)
    -- general
    mink.args = {...}
    mink.cmd_call = w_mink_lua_cmd_call
    return mink
end

-- return module init method
return init
