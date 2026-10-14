-- ngx.log(ngx.ERR, "PP=", ngx.var.product_id)
local ssl                = require "ngx.ssl"
local ngx_md5            = ngx.md5
local strlen             = string.len
local lrucache           = require "resty.lrucache"
local cjson              = require "cjson"

local lrucache_items_max = 8192
local cache_method       = "lrucache"
local ECDSA_NONE         = "none"
local NEGATIVE_TTL       = 60
local LOG_DEDUP_SECONDS  = 300
local LOG_WINDOW_SECONDS = 60
local LOG_WINDOW_MAX     = 20
local SWEEP_INTERVAL     = 300
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

local negatives          = lrucache.new(2048)
local log_seen_config    = lrucache.new(1024)
local log_seen_client    = lrucache.new(1024)
local log_window_start   = 0
local log_window_count   = 0
local log_suppressed     = 0
local next_sweep_at      = 0
local last_sweep_at      = 0
local last_sweep_removed = 0

---log_config
---Problems of the certificate files themselves: logged once per key per LOG_DEDUP_SECONDS
---@param level number
---@param key string
---@return nil
local function log_config(level, key, ...)
    if log_seen_config:get(key) then
        return
    end
    log_seen_config:set(key, true, LOG_DEDUP_SECONDS)
    ngx.log(level, ...)
end

---log_client
---Client driven noise (unknown or empty SNI): deduplicated like log_config, plus at most LOG_WINDOW_MAX lines per LOG_WINDOW_SECONDS per worker
---@param level number
---@param key string
---@return nil
local function log_client(level, key, ...)
    if log_seen_client:get(key) then
        return
    end
    local now = ngx.now()
    if now - log_window_start >= LOG_WINDOW_SECONDS then
        if log_suppressed > 0 then
            ngx.log(ngx.WARN, "dynamic-ssl: suppressed ", log_suppressed, " client log messages in the last ", LOG_WINDOW_SECONDS, "s")
        end
        log_window_start = now
        log_window_count = 0
        log_suppressed = 0
    end
    if log_window_count >= LOG_WINDOW_MAX then
        log_suppressed = log_suppressed + 1
        return
    end
    log_window_count = log_window_count + 1
    log_seen_client:set(key, true, LOG_DEDUP_SECONDS)
    ngx.log(level, ...)
end

---sweep_lru
---lrucache keeps expired values until overwritten or evicted; walk keys LRU first so the recency order is preserved
---@param cache table
---@return number
local function sweep_lru(cache)
    local keys = cache:get_keys(0)
    local removed = 0
    for i = #keys, 1, -1 do
        if cache:get(keys[i]) == nil then
            cache:delete(keys[i])
            removed = removed + 1
        end
    end
    return removed
end

---sweep_expired
---@return number
local function sweep_expired()
    local removed = 0
    if cache_method == "lua_shared_dict" then
        removed = certs:flush_expired() + certs_content:flush_expired()
    elseif certs and certs_content then
        removed = sweep_lru(certs) + sweep_lru(certs_content)
    end
    return removed + sweep_lru(negatives)
end

---maybe_sweep
---Runs sweep_expired inline at most once per SWEEP_INTERVAL per worker
---@return nil
local function maybe_sweep()
    local now = ngx.now()
    if now < next_sweep_at then
        return
    end
    next_sweep_at = now + SWEEP_INTERVAL
    local ok, removed = pcall(sweep_expired)
    if not ok then
        log_config(ngx.ERR, "sweep", "cache sweep failed: ", removed)
        return
    end
    last_sweep_at = math.floor(now)
    last_sweep_removed = removed
end

---set_sni_name
---Normalize SNI name to lowercase
---@param self DynamicSSLClass
---@return boolean
local function set_sni_name(self)
    local sni_name, err = ssl.server_name()
    if not sni_name then
        log_client(ngx.WARN, "empty-sni", "Empty SNI name")
        return false
    end
    self._sni_name = sni_name:lower()
    return true
end

---get_cache_key_names_by_sni_name
---@param self DynamicSSLClass
---@param sni_name string
---@param suffix string|nil
---@return string, string
local function get_cache_key_names_by_sni_name(self, sni_name, suffix)
    suffix = suffix or ""
    local prefix = (self.file_cert or self.dir_base) .. "/" .. sni_name
    local _key_cert = prefix .. "_crt" .. suffix .. "." .. self.method
    local _key_priv = prefix .. "_key" .. suffix .. "." .. self.method
    return _key_cert, _key_priv
end

---set_cache_keys
---@param self DynamicSSLClass
---@return boolean
local function set_cache_keys(self)
    local kc, kp = get_cache_key_names_by_sni_name(self, self._sni_name)
    self.cache._key_cert = kc
    self.cache._key_priv = kp
    kc, kp = get_cache_key_names_by_sni_name(self, self._sni_name, "_ecdsa")
    self.cache._key_cert_ecdsa = kc
    self.cache._key_priv_ecdsa = kp
    return true
end

---cache_lookup_pair
---@param self DynamicSSLClass
---@param key_cert string
---@param key_priv string
---@return any, any
local function cache_lookup_pair(self, key_cert, key_priv)
    local content_key_crt = certs:get(key_cert)
    if not content_key_crt or strlen(content_key_crt) ~= 32 then
        return nil
    end
    local content_key_priv = certs:get(key_priv)
    if not content_key_priv or strlen(content_key_priv) ~= 32 then
        return nil
    end

    local cache_crt_content = certs_content:get(content_key_crt .. "." .. self.method)
    if not cache_crt_content then
        return nil
    end

    local cache_key_content = certs_content:get(content_key_priv .. "." .. self.method)
    if not cache_key_content then
        return nil
    end
    return cache_crt_content, cache_key_content
end

---cache_lookup
---@param self DynamicSSLClass
---@return table
local function cache_lookup(self)
    local result = {
        success = false,
        missing = false,
        content = {
            cert = false,
            priv = false,
            cert_ecdsa = false,
            priv_ecdsa = false
        }
    }

    if negatives:get(self.cache._key_cert) then
        result.missing = true
        return result
    end

    local crt, priv = cache_lookup_pair(self, self.cache._key_cert, self.cache._key_priv)
    if not crt then
        return result
    end

    local crt_ecdsa, priv_ecdsa = false, false
    if self.ecdsa and certs:get(self.cache._key_cert_ecdsa) ~= ECDSA_NONE then
        crt_ecdsa, priv_ecdsa = cache_lookup_pair(self, self.cache._key_cert_ecdsa, self.cache._key_priv_ecdsa)
        if not crt_ecdsa then
            return result
        end
    end

    result.success = true
    result.content.cert = crt
    result.content.priv = priv
    result.content.cert_ecdsa = crt_ecdsa
    result.content.priv_ecdsa = priv_ecdsa
    return result
end

---read_file
---@param path string
---@return string|nil
local function read_file(path)
    local f = io.open(path, "rb")
    if not f then
        return nil
    end
    local content = f:read("*all")
    f:close()
    return content
end

---convert_pair
---@param self DynamicSSLClass
---@param crt_content string
---@param key_content string
---@param label string
---@return any, any
local function convert_pair(self, crt_content, key_content, label)
    local crt_bin, key_bin, err
    if self.method == "der" then
        crt_bin, err = ssl.cert_pem_to_der(crt_content)
        if not crt_bin then
            log_config(ngx.ERR, "convert-crt:" .. label, "failed to convert crt from PEM to DER: ", label, ": ", err)
            return nil
        end

        key_bin, err = ssl.priv_key_pem_to_der(key_content)
        if not key_bin then
            log_config(ngx.ERR, "convert-key:" .. label, "failed to convert private key from PEM to DER: ", label, ": ", err)
            return nil
        end
    elseif self.method == "opaque" then
        crt_bin, err = ssl.parse_pem_cert(crt_content)
        if not crt_bin then
            log_config(ngx.ERR, "convert-crt:" .. label, "failed to convert crt from PEM to opaque cdata: ", label, ": ", err)
            return nil
        end

        key_bin, err = ssl.parse_pem_priv_key(key_content)
        if not key_bin then
            log_config(ngx.ERR, "convert-key:" .. label, "failed to convert private key from PEM to opaque cdata: ", label, ": ", err)
            return nil
        end
    end
    return crt_bin, key_bin
end

---file_lookup_ecdsa
---@param self DynamicSSLClass
---@param result table
---@return nil
local function file_lookup_ecdsa(self, result)
    local f_crt = self.dir_base .. "/" .. self._sni_name .. ".ecdsa.crt"
    local f_key = self.dir_base .. "/" .. self._sni_name .. ".ecdsa.key"
    if self.file_cert then
        if not self.file_cert_ecdsa then
            return
        end
        f_crt = self.file_cert_ecdsa
        f_key = self.file_key_ecdsa
    end

    local crt_content = read_file(f_crt)
    if not crt_content then
        return
    end

    local key_content = read_file(f_key)
    if not key_content then
        log_config(ngx.WARN, "ecdsa-key:" .. f_key, "Missing ecdsa key: ", f_key)
        return
    end

    local crt_bin, key_bin = convert_pair(self, crt_content, key_content, f_crt)
    if not crt_bin then
        return
    end

    result.path.cert_ecdsa = f_crt
    result.path.priv_ecdsa = f_key
    result.file.cert_ecdsa = crt_content
    result.file.priv_ecdsa = key_content
    result.content.cert_ecdsa = crt_bin
    result.content.priv_ecdsa = key_bin
end

---file_lookup
---@param self DynamicSSLClass
---@return table
local function file_lookup(self)
    local result = {
        success = false,
        path = {
            cert = "",
            priv = "",
            cert_ecdsa = false,
            priv_ecdsa = false
        },
        file = {
            cert = "",
            priv = "",
            cert_ecdsa = false,
            priv_ecdsa = false
        },
        content = {
            cert = false,
            priv = false,
            cert_ecdsa = false,
            priv_ecdsa = false
        }
    }

    -- Load cert
    local f_crt = self.dir_base .. "/" .. self._sni_name .. ".crt"
    if self.file_cert then
        f_crt = self.file_cert
    end
    result.path.cert = f_crt
    local crt_content = read_file(f_crt)
    if not crt_content then
        log_client(ngx.WARN, "crt:" .. f_crt, "Missing certificate: ", f_crt)
        return result
    end

    -- Load private key
    local f_key = self.dir_base .. "/" .. self._sni_name .. ".key"
    if self.file_key then
        f_key = self.file_key
    end
    result.path.priv = f_key
    local key_content = read_file(f_key)
    if not key_content then
        log_config(ngx.ERR, "key:" .. f_key, "Missing key: ", f_key)
        return result
    end

    local crt_bin, key_bin = convert_pair(self, crt_content, key_content, f_crt)
    if not crt_bin then
        return result
    end

    if self.ecdsa then
        file_lookup_ecdsa(self, result)
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
---@param file table
---@return boolean
local function save_cache(self, file)
    if self.cache.enabled == false then
        return false
    end
    if self.computed.cert == nil or self.computed.priv == nil then
        return false
    end

    local crt_md5_hex = ngx_md5(file.cert)
    local key_md5_hex = ngx_md5(file.priv)

    if self.ecdsa then
        local crt_ecdsa_md5_hex, key_ecdsa_md5_hex = ECDSA_NONE, ECDSA_NONE
        if self.computed.cert_ecdsa then
            crt_ecdsa_md5_hex = ngx_md5(file.cert_ecdsa)
            key_ecdsa_md5_hex = ngx_md5(file.priv_ecdsa)
            certs_content:set(key_ecdsa_md5_hex .. "." .. self.method, self.computed.priv_ecdsa, self.cache.seconds)
            certs_content:set(crt_ecdsa_md5_hex .. "." .. self.method, self.computed.cert_ecdsa, self.cache.seconds)
        end
        certs:set(self.cache._key_cert_ecdsa, crt_ecdsa_md5_hex, self.cache.seconds)
        if key_ecdsa_md5_hex ~= ECDSA_NONE then
            certs:set(self.cache._key_priv_ecdsa, key_ecdsa_md5_hex, self.cache.seconds)
        end
    end

    certs_content:set(key_md5_hex .. "." .. self.method, self.computed.priv, self.cache.seconds)
    certs_content:set(crt_md5_hex .. "." .. self.method, self.computed.cert, self.cache.seconds)
    certs:set(self.cache._key_cert, crt_md5_hex, self.cache.seconds)
    certs:set(self.cache._key_priv, key_md5_hex, self.cache.seconds)
    return true
end

---set_pair
---@param self DynamicSSLClass
---@param cert any
---@param priv any
---@return boolean
local function set_pair(self, cert, priv)
    local ok, err
    if self.method == "der" then
        ok, err = ssl.set_der_cert(cert)
        if not ok then
            log_config(ngx.ERR, "set-crt:" .. self._sni_name, "failed to set DER cert: ", self._sni_name, ": ", err)
            return false
        end

        ok, err = ssl.set_der_priv_key(priv)
        if not ok then
            log_config(ngx.ERR, "set-key:" .. self._sni_name, "failed to set DER private key: ", self._sni_name, ": ", err)
            return false
        end
    elseif self.method == "opaque" then
        ok, err = ssl.set_cert(cert)
        if not ok then
            log_config(ngx.ERR, "set-crt:" .. self._sni_name, "failed to set opaque cdata cert: ", self._sni_name, ": ", err)
            return false
        end

        ok, err = ssl.set_priv_key(priv)
        if not ok then
            log_config(ngx.ERR, "set-key:" .. self._sni_name, "failed to set opaque cdata key: ", self._sni_name, ": ", err)
            return false
        end
    end
    return true
end

---handle_ssl
---Do the actual work. Replace the current/default ssl certificate with the dynamic version if its available.
---OpenSSL keeps RSA and ECDSA in separate slots and picks one per handshake based on the client's signature algorithms.
---@param self DynamicSSLClass
---@return boolean
local function handle_ssl(self)
    local ok = ssl.clear_certs()
    if not ok then
        log_config(ngx.ERR, "clear-certs", "failed to clear existing (fallback) certificates")
        return false
    end

    if self.computed.cert_ecdsa then
        if set_pair(self, self.computed.cert_ecdsa, self.computed.priv_ecdsa) then
            self.ctx.ecdsa = true
        else
            ok = ssl.clear_certs()
            if not ok then
                log_config(ngx.ERR, "clear-certs-ecdsa", "failed to clear certificates after ecdsa failure")
                return false
            end
        end
    end

    return set_pair(self, self.computed.cert, self.computed.priv)
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
    negatives:flush_all()
    return rc
end

---get_cache_stats
---@param self DynamicSSLClass
---@return table
local function get_cache_stats(self)
    local res = {
        available = false,
        method = cache_method,
        last_sweep_at = last_sweep_at,
        last_sweep_removed = last_sweep_removed,
        capacity = {
            certs = 0,
            certs_content = 0,
            negatives = negatives:capacity()
        },
        free_space = {
            certs = 0,
            certs_content = 0,
            negatives = negatives:capacity() - negatives:count()
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
    for _, suffix in ipairs({ "", "_ecdsa" }) do
        local cache_key_cert, cache_key_priv = get_cache_key_names_by_sni_name(self, sni_name, suffix)
        if negatives:delete(cache_key_cert) then
            modified = modified + 1
        end
        for _, cache_key in ipairs({ cache_key_cert, cache_key_priv }) do
            local certs_content_md5 = certs:get(cache_key)
            if certs_content_md5 then
                if certs:delete(cache_key) then
                    modified = modified + 1
                end
                if certs_content_md5 ~= ECDSA_NONE and certs_content:delete(certs_content_md5 .. "." .. self.method) then
                    modified = modified + 1
                end
            end
        end
    end
    return modified
end

---@class DynamicSSLClass
local _M = {
    _VERSION = 2026101301
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
            _key_priv = false,
            _key_cert_ecdsa = false,
            _key_priv_ecdsa = false
        },
        computed = {
            cert = nil,
            priv = nil,
            cert_ecdsa = false,
            priv_ecdsa = false
        },
        ctx = {
            method = "",
            cache_method = cache_method,
            source = "none",
            ecdsa = false,
            result = 0
        },
        product_id = product_id,
        dir_certs = dir_certs,
        dir_base = dir_certs .. "/" .. product_id,
        file_cert = false,
        file_key = false,
        file_cert_ecdsa = false,
        file_key_ecdsa = false,
        ecdsa = false,
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
---Override default dir checking, use files instead from input params. The ECDSA pair is used only after set_ecdsa(true)
---@param self DynamicSSLClass
---@param path_crt string
---@param path_key string
---@param path_crt_ecdsa string|nil
---@param path_key_ecdsa string|nil
---@return boolean
function _M.set_certificate_path(self, path_crt, path_key, path_crt_ecdsa, path_key_ecdsa)
    if not path_crt or type(path_crt) ~= "string" then
        return false
    end
    if not path_key or type(path_key) ~= "string" then
        return false
    end
    if path_crt_ecdsa ~= nil or path_key_ecdsa ~= nil then
        if type(path_crt_ecdsa) ~= "string" or type(path_key_ecdsa) ~= "string" then
            return false
        end
        self.file_cert_ecdsa = path_crt_ecdsa
        self.file_key_ecdsa = path_key_ecdsa
    end
    self.file_cert = path_crt
    self.file_key = path_key
    return true
end

---set_ecdsa
---Load the optional <sni>.ecdsa.crt / <sni>.ecdsa.key pair next to the RSA pair, default: off
---@param self DynamicSSLClass
---@param enabled boolean
---@return boolean
function _M.set_ecdsa(self, enabled)
    if type(enabled) ~= "boolean" then
        return false
    end
    self.ecdsa = enabled
    return true
end

---exec
---Failed lookups are cached in a separate negative cache for min(NEGATIVE_TTL, cache_seconds)
---@param self DynamicSSLClass
---@return boolean
function _M.exec(self)
    maybe_sweep()
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
        if cache_result.missing then
            self.ctx.source = "cache:missing"
        elseif cache_result.success == true then
            self.computed.cert = cache_result.content.cert
            self.computed.priv = cache_result.content.priv
            self.computed.cert_ecdsa = cache_result.content.cert_ecdsa
            self.computed.priv_ecdsa = cache_result.content.priv_ecdsa
            found_valid_cert = true
            self.ctx.source = "cache:" .. cache_method
        end
    end

    if found_valid_cert == false and self.ctx.source ~= "cache:missing" then
        local file_result = file_lookup(self)
        if file_result.success == true then
            self.computed.cert = file_result.content.cert
            self.computed.priv = file_result.content.priv
            self.computed.cert_ecdsa = file_result.content.cert_ecdsa
            self.computed.priv_ecdsa = file_result.content.priv_ecdsa
            save_cache(self, file_result.file)
            found_valid_cert = true
            self.ctx.source = "file:" .. file_result.path.cert .. "|" .. file_result.path.priv
            if file_result.path.cert_ecdsa then
                self.ctx.source = self.ctx.source .. "|" .. file_result.path.cert_ecdsa .. "|" .. file_result.path.priv_ecdsa
            end
        end
    end

    if found_valid_cert then
        if handle_ssl(self) then
            self.ctx.result = 1
            ngx.ctx.DYNAMIC_SSL = self.ctx
            return true
        end
    end
    if self.cache.enabled and self.ctx.source ~= "cache:missing" then
        local ttl = NEGATIVE_TTL
        if self.cache.seconds < ttl then
            ttl = self.cache.seconds
        end
        negatives:set(self.cache._key_cert, true, ttl)
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
