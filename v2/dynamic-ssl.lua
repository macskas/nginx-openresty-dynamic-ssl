-- ngx.log(ngx.ERR, "PP=", ngx.var.product_id)
local resty_md5          = require "resty.md5"
local ssl                = require "ngx.ssl"
local str                = require "resty.string"
local strlen             = string.len
local lrucache           = require "resty.lrucache"
local cjson              = require "cjson"

local lrucache_items_max = 512
local cache_method       = "lrucache"
local certs              = nil
local certs_content      = nil

if cache_method == "lrucache" then
    certs = lrucache.new(lrucache_items_max)
    certs_content = lrucache.new(lrucache_items_max)
elseif cache_method == "lua_shared_dict" then
    -- opaque method is not working with lua_shared_dict, but its a global cache
    certs = ngx.shared.certs
    certs_content = ngx.shared.certs_content
end

---set_sni_name
---Normalize SNI name to lowercase
---@param self DynamicSSLClass
---@return boolean
local function set_sni_name(self)
    local sni_name, err = ssl.server_name()
    if not sni_name then
        ngx.log(ngx.ERR, "Empty SNI name")
        return false
    end
    self._sni_name = sni_name:lower()
    return true
end

---get_cache_key_names_by_sni_name
---@param self DynamicSSLClass
---@param sni_name string
---@return string, string
local function get_cache_key_names_by_sni_name(self, sni_name)
    local _key_cert = sni_name .. "_crt." .. self.method
    local _key_priv = sni_name .. "_key." .. self.method
    return _key_cert, _key_priv
end

---set_cache_keys
---@param self DynamicSSLClass
---@return boolean
local function set_cache_keys(self)
    local kc, kp = get_cache_key_names_by_sni_name(self, self._sni_name)
    self.cache._key_cert = kc
    self.cache._key_priv = kp
    return true
end

---cache_lookup
---@param self DynamicSSLClass
---@return table
local function cache_lookup(self)
    local result = {
        success = false,
        content = {
            cert = false,
            priv = false
        }
    }

    local content_key_crt = certs:get(self.cache._key_cert)
    if not content_key_crt or strlen(content_key_crt) ~= 32 then
        return result
    end
    local content_key_priv = certs:get(self.cache._key_priv)
    if not content_key_priv or strlen(content_key_priv) ~= 32 then
        return result
    end

    local cache_crt_content = certs_content:get(content_key_crt)
    if not cache_crt_content then
        return result
    end

    local cache_key_content = certs_content:get(content_key_priv)
    if not cache_key_content then
        return result
    end

    result.success = true
    result.content.cert = cache_crt_content
    result.content.priv = cache_key_content
    return result
end

---file_lookup
---@param self DynamicSSLClass
---@return table
local function file_lookup(self)
    local result = {
        success = false,
        path = {
            cert = "",
            priv = ""
        },
        file = {
            cert = "",
            priv = ""
        },
        content = {
            cert = false,
            priv = false
        }
    }

    local f, err
    -- Load cert
    local f_crt = self.dir_base .. "/" .. self._sni_name .. ".crt"
    if self.file_cert then
        f_crt = self.file_cert
    end
    result.path.cert = f_crt
    f = io.open(f_crt, "rb")
    if not f then
        ngx.log(ngx.ERR, "Missing certificate: " .. f_crt)
        return result
    end
    local crt_content = f:read("*all")
    f:close()
    f = nil

    -- Load private key
    local f_key = self.dir_base .. "/" .. self._sni_name .. ".key"
    if self.file_key then
        f_key = self.file_key
    end
    result.path.priv = f_key
    f = io.open(f_key, "rb")
    if not f then
        ngx.log(ngx.ERR, "Missing key: " .. f_key)
        return result
    end
    local key_content = f:read("*all")
    f:close()
    f = nil


    local crt_bin, key_bin
    if self.method == "der" then
        crt_bin, err = ssl.cert_pem_to_der(crt_content)
        if not crt_bin then
            ngx.log(ngx.ERR, "failed to convert crt ", "from PEM to DER: ", err)
            return result
        end

        key_bin, err = ssl.priv_key_pem_to_der(key_content)
        if not key_bin then
            ngx.log(ngx.ERR, "failed to convert private key ", "from PEM to DER: ", err)
            return result
        end
    elseif self.method == "opaque" then
        crt_bin, err = ssl.parse_pem_cert(crt_content)
        if not crt_bin then
            ngx.log(ngx.ERR, "failed to convert crt ", "from PEM to opaque cdata: ", err)
            return result
        end

        key_bin, err = ssl.parse_pem_priv_key(key_content)
        if not key_bin then
            ngx.log(ngx.ERR, "failed to convert private key ", "from PEM to opaque cdata: ", err)
            return result
        end
    end

    result.file.cert = crt_content
    result.file.priv = key_content
    result.content.cert = crt_bin
    result.content.priv = key_bin
    result.success = true
    return result
end

---save_cache
---@param self DynamicSSLClass
---@param content_cert string
---@param content_priv string
---@return boolean
local function save_cache(self, content_cert, content_priv)
    if self.cache.enabled == false then
        return false
    end
    if self.computed.cert == nil or self.computed.priv == nil then
        return false
    end

    local md5 = resty_md5:new()
    if not md5 then
        ngx.log(ngx.ERR, "failed to create md5 object")
        return false
    end

    -- update crt cache
    local crt_md5_hex
    md5:update(content_cert)
    local crt_md5_chr = md5:final()
    if crt_md5_chr then
        crt_md5_hex = str.to_hex(crt_md5_chr)
    end
    md5:reset()

    -- update crt cache
    local key_md5_hex
    md5:update(content_priv)
    local key_md5_chr = md5:final()
    if key_md5_chr then
        key_md5_hex = str.to_hex(key_md5_chr)
    end
    md5:reset()

    if crt_md5_hex and strlen(crt_md5_hex) == 32 and key_md5_hex and strlen(key_md5_hex) == 32 then
        certs:set(self.cache._key_cert, crt_md5_hex, self.cache.seconds)
        certs:set(self.cache._key_priv, key_md5_hex, self.cache.seconds)
        certs_content:set(key_md5_hex, self.computed.priv, self.cache.seconds)
        certs_content:set(crt_md5_hex, self.computed.cert, self.cache.seconds)
        return true
    end
    return false
end

---handle_ssl
---Do the actual work. Replace the current/default ssl certificate with the dynamic version if its available.
---@param self DynamicSSLClass
---@return boolean
local function handle_ssl(self)
    local ok, err = ssl.clear_certs()
    if not ok then
        ngx.log(ngx.ERR, "failed to clear existing (fallback) certificates")
        return false
    end

    if self.method == "der" then
        ok, err = ssl.set_der_cert(self.computed.cert)
        if not ok then
            ngx.log(ngx.ERR, "failed to set DER cert: ", err)
            return false
        end

        ok, err = ssl.set_der_priv_key(self.computed.priv)
        if not ok then
            ngx.log(ngx.ERR, "failed to set DER private key: ", err)
            return false
        end
    elseif self.method == "opaque" then
        ok, err = ssl.set_cert(self.computed.cert)
        if not ok then
            ngx.log(ngx.ERR, "failed to set opaque cdata cert: ", err)
            return false
        end

        ok, err = ssl.set_priv_key(self.computed.priv)
        if not ok then
            ngx.log(ngx.ERR, "failed to set opaque cdata key: ", err)
            return false
        end
    end
    return true
end


---flush_cache
---@param self DynamicSSLClass
---@return number
local function flush_cache(self)
    local rc = 0
    if certs then
        certs:flush_all()
        rc = 1
    end
    if certs_content then
        certs_content:flush_all()
        rc = rc+1
    end
    return rc
end

---get_cache_stats
---@param self DynamicSSLClass
---@return table
local function get_cache_stats(self)
    local res = {
        available = false,
        method = cache_method,
        capacity = {
            certs = 0,
            certs_content = 0
        },
        free_space = {
            certs = 0,
            certs_content = 0
        }
    }
    if not certs or not certs_content then
        return res
    end
    res.available = true
    if cache_method == "lua_shared_dict" then
        res.capacity.certs = certs:capacity()
        res.capacity.certs_content = certs_content:capacity()
        res.free_space.certs = certs:free_space()
        res.free_space.certs_content = certs_content:free_space()
    elseif cache_method == "lrucache" then
        res.capacity.certs = certs:capacity()
        res.capacity.certs_content = certs_content:capacity()
        res.free_space.certs = res.capacity.certs - certs:count()
        res.free_space.certs_content = res.capacity.certs_content - certs_content:count()
    end
    return res
end

---delete_cache_item
---@param self DynamicSSLClass
---@param input_sni_name string
---@return number
local function delete_cache_item(self, input_sni_name)
    local sni_name = input_sni_name:lower()
    local modified = 0
    local cache_key_cert, cache_key_priv = get_cache_key_names_by_sni_name(self, sni_name)
    local certs_content_md5_cert = certs:get(cache_key_cert)
    if certs_content_md5_cert then
        if certs:delete(cache_key_cert) then
            modified = modified + 1
        end
        if certs_content:delete(certs_content_md5_cert) then
            modified = modified + 1
        end
    end

    local certs_content_md5_priv = certs:get(cache_key_priv)
    if certs_content_md5_priv then
        if certs:delete(cache_key_priv) then
            modified = modified + 1
        end
        if certs_content:delete(certs_content_md5_priv) then
            modified = modified + 1
        end
    end
    return modified
end

---@class DynamicSSLClass
local _M = {
    _VERSION = 2021012001
}
local mt = { __index = _M }

---@return DynamicSSLClass
---@param _self DynamicSSLClass
---@param dir_certs string
---@param product_id string
---@param cache_seconds number
---@param fallback boolean
function _M.new(_self, dir_certs, product_id, cache_seconds, fallback)
    local self = {
        method = "der",
        cache = {
            seconds = cache_seconds,
            enabled = false,
            _key_cert = false,
            _key_priv = false
        },
        computed = {
            cert = nil,
            priv = nil
        },
        ctx = {
            method = "",
            cache_method = cache_method,
            source = "none",
            result = 0
        },
        product_id = product_id,
        dir_certs = dir_certs,
        dir_base = dir_certs .. "/" .. product_id,
        file_cert = false,
        file_key = false,
        fallback = false,
        _sni_name = ""
    }

    if type(cache_seconds) == "number" and cache_seconds > 0 and certs ~= nil and certs_content ~= nil then
        self.cache.enabled = true
    end

    if fallback then
        self.fallback = true
    end

    return setmetatable(self, mt)
end

---set_certificate_path
---Override default dir checking, use files instead from input params
---@param self DynamicSSLClass
---@param path_crt string
---@param path_key string
---@return boolean
function _M.set_certificate_path(self, path_crt, path_key)
    if not path_crt or type(path_crt) ~= "string" then
        return false
    end
    if not path_key or type(path_key) ~= "string" then
        return false
    end
    self.file_cert = path_crt
    self.file_key = path_key
    return true
end

---exec
---@param self DynamicSSLClass
---@return boolean
function _M.exec(self)
    if set_sni_name(self) == false then
        if self.fallback then
            return false
        else
            ngx.exit(ngx.ERROR)
        end
    end

    self.ctx.method = self.method
    local found_valid_cert = false
    if self.cache.enabled then
        if not certs or not certs_content then
            self.cache.enabled = false
        end
    end
    if self.cache.enabled then
        set_cache_keys(self)
        local cache_result = cache_lookup(self)
        if cache_result.success == true then
            self.computed.cert = cache_result.content.cert
            self.computed.priv = cache_result.content.priv
            found_valid_cert = true
            self.ctx.source = "cache:" .. cache_method
        end
    end

    if found_valid_cert == false then
        local file_result = file_lookup(self)
        if file_result.success == true then
            self.computed.cert = file_result.content.cert
            self.computed.priv = file_result.content.priv
            save_cache(self, file_result.file.cert, file_result.file.priv)
            found_valid_cert = true
            self.ctx.source = "file:" .. file_result.path.cert .. "|" .. file_result.path.priv
        end
    end

    if found_valid_cert then
        if handle_ssl(self) then
            self.ctx.result = 1
            ngx.ctx.DYNAMIC_SSL = self.ctx
            return true
        end
    end
    ngx.ctx.DYNAMIC_SSL = self.ctx

    if self.fallback then
        return false
    else
        ngx.exit(ngx.ERROR)
    end
end

---set_cert_process_method
---Set process method. Use std DER format or opaque cdata. Valid methods: opaque|der, default: der
---@param self DynamicSSLClass
---@param cert_process_method string
---@return boolean
function _M.set_cert_process_method(self, cert_process_method)
    local valid_methods = {
        opaque = 1,
        der = 1
    }
    if type(cert_process_method) ~= "string" then
        return false
    end
    if not ssl.parse_pem_priv_key then
        valid_methods.opaque = nil
    end
    if not valid_methods[cert_process_method] then
        return false
    end
    self.method = cert_process_method
    return true
end

---handle_route
---Handle /dssl/ route for debug, cache management
---@param self DynamicSSLClass
---@return nil
function _M.handle_route(self)
    local ruri = ngx.var.uri or ""
    ngx.header["Content-Type"] = "application/json"
    local res = {
        success = false,
        code = 200,
        message = "OK",
        data = false
    }
    if ruri:find("/dssl/flush%-cache/") then
        local rc = flush_cache(self)
        res.success = true
        res.message = string.format("OK (flush_ok: %d)", rc)
    elseif ruri:find("/dssl/get%-cache%-stats/") then
        res.success = true
        res.data = get_cache_stats(self)
    elseif ruri:find("/dssl/flush%-cache%-domain/") then
        local sni_name = ngx.var.arg_domain or ""
        sni_name = sni_name:lower()
        if strlen(sni_name) > 0 then
            local modified = delete_cache_item(self, sni_name)
            res.success = true
            res.message = string.format("OK (modified: %d)", modified)
        else
            res.success = false
            res.message = "Missing get param: domain"
            res.code = 400
        end
    else
        res.success = false
        res.code = 404
        res.message = "Not found"
    end

    ngx.print(cjson.encode(res))
    ngx.exit(res.code)
end

return _M
