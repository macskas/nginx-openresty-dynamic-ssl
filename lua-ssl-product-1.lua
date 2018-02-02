-- ngx.log(ngx.ERR, "PP=", ngx.var.product_id)
local resty_md5     = require "resty.md5"
local ssl           = require "ngx.ssl"
local str           = require "resty.string"
local certs         = ngx.shared.certs
local certs_content = ngx.shared.certs_content
local cache_seconds = 600
local product_id    = "1"
local dir_certs     = "/etc/letsencrypt"
local dir_base      = dir_certs .. "/" .. product_id
local strlen        = string.len

-- Check if browser supports SNI
local sni_name, err = ssl.server_name()
if not sni_name then
    ngx.log(ngx.ERR, "Empty SNI name")
    return ngx.exit(ngx.ERROR)
end

-- Init MD5 functions
local md5 = resty_md5:new()
if not md5 then
    ngx.log(ngx.ERR, "failed to create md5 object")
    ngx.exit(ngx.ERROR)
end

local cache_enabled = 1
local cache_crt_md5
local cache_key_md5
local cache_crt_content
local cache_key_content
local crt_md5_hex
local key_md5_hex

if cache_enabled then
    cache_crt_md5 = certs:get(sni_name .. "_crt")
    if not cache_crt_md5 or strlen(cache_crt_md5) ~= 32 then
        cache_enabled = 0
    end

    cache_key_md5 = certs:get(sni_name .. "_key")
    if not cache_key_md5 or strlen(cache_key_md5) ~= 32 then
        cache_enabled = 0
    end
end

if cache_enabled == 1 then
    cache_crt_content = certs_content:get(cache_crt_md5)
    cache_key_content = certs_content:get(cache_key_md5)

    if not cache_crt_content or strlen(cache_crt_content) < 50 then
        cache_enabled = 0
    end

    if not cache_key_content or strlen(cache_key_content) < 50 then
        cache_enabled = 0
    end
end

local crt_content
-- Handle not cached crt
if cache_enabled == 0 then
    local f_crt = dir_base .. "/" .. sni_name .. ".crt"
    local f = io.open(f_crt, "rb")
    if not f then
        ngx.log(ngx.ERR, "Missing certificate: " .. f_crt)
        return ngx.exit(ngx.ERROR)
    end
    crt_content = f:read("*all")
    f:close()

    -- update crt cache
    local crt_md5_chr
    md5:update(crt_content)
    crt_md5_chr = md5:final()
    if crt_md5_chr then
        crt_md5_hex = str.to_hex(crt_md5_chr)
    end
    md5:reset()

    if crt_md5_hex and strlen(crt_md5_hex) == 32 then
        certs:set(sni_name .. "_crt", crt_md5_hex, cache_seconds)
    end
end

-- Handle not cached key
local key_content
if cache_enabled == 0 then
    local f_key = dir_base .. "/" .. sni_name .. ".key"
    local f = io.open(f_key, "rb")
    if not f then
        return ngx.exit(ngx.ERROR)
    end
    key_content = f:read("*all")
    f:close()

    -- update key cache
    local key_md5_chr
    md5:update(key_content)
    key_md5_chr = md5:final()
    if key_md5_chr then
        key_md5_hex = str.to_hex(key_md5_chr)
    end

    md5:reset()
    if key_md5_hex and strlen(key_md5_hex) == 32 then
        certs:set(sni_name .. "_key", key_md5_hex, cache_seconds)
    end
end

local ok, err = ssl.clear_certs()
if not ok then
    ngx.log(ngx.ERR, "failed to clear existing (fallback) certificates")
    return ngx.exit(ngx.ERROR)
end

-- convert and load CRT in(to) DER format
local crt_der
if cache_enabled == 0 then
    local err
    crt_der, err = ssl.cert_pem_to_der(crt_content)
    if not crt_der then
        ngx.log(ngx.ERR, "failed to convert crt ", "from PEM to DER: ", err)
        return ngx.exit(ngx.ERROR)
    end
    certs_content:set(crt_md5_hex, crt_der, cache_seconds)
else
    crt_der = cache_crt_content
end

local ok, err = ssl.set_der_cert(crt_der)
if not ok then
    ngx.log(ngx.ERR, "failed to set DER cert: ", err)
    return ngx.exit(ngx.ERROR)
end

-- convert and load KEY in(to) DER format
local key_der
if cache_enabled == 0 then
    local err
    key_der, err = ssl.priv_key_pem_to_der(key_content)
    if not key_der then
        ngx.log(ngx.ERR, "failed to convert private key ", "from PEM to DER: ", err)
        return ngx.exit(ngx.ERROR)
    end
    certs_content:set(key_md5_hex, key_der, cache_seconds)
else
    key_der = cache_key_content
end

local ok, err = ssl.set_der_priv_key(key_der)
if not ok then
    ngx.log(ngx.ERR, "failed to set DER private key: ", err)
    return ngx.exit(ngx.ERROR)
end

-- ngx.log(ngx.ERR, "Cached data=", cache_enabled)
