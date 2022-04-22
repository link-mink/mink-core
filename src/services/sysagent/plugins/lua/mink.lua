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
    int mink_lua_cmd_call(void *md, int argc, const char **args);
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
    -- call C method
    return C.mink_lua_cmd_call(mink.args[1], l, c_array)
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
