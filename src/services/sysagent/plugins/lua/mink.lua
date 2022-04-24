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
    void free(void *p);
    int mink_lua_cmd_call(void *md,
                          int argc,
                          const char **args,
                          char ***out,
                          int *out_sz);
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
    local c_out = ffi.new("char **[1]")
    local c_out_sz = ffi.new("int [1]")
    -- call C method
    local res = C.mink_lua_cmd_call(mink.args[1],
                                    l,
                                    c_array,
                                    c_out,
                                    c_out_sz)
    -- if successful, copy C data to lua table
    if res == 0 then
        -- result
        local res = {}
        -- create result from c array
        for i = 0, c_out_sz[0] - 1 do
            -- c string to lua string
            res[i + 1] = ffi.string(c_out[0][i])
            -- free c string later
            ffi.gc(c_out[0][i], ffi.C.free)
        end
        -- free c array later
        ffi.gc(c_out[0], ffi.C.free)
        -- return lua table
        return res
    end
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
