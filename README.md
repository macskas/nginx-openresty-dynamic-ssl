# nginx-openresty-dynamic-ssl
nginx openresty dynamic ssl lua script + cache

There is an auto letsencrypt nginx lua module out there. But good luck using it and using it safely in a load-balanced environment and without letsencrypt.

With this script, cert generation is a different process(not included) and this is only using the pre-generated certs/keys.

There are two versions:

- `v2/dynamic-ssl.lua` - lua module, RSA + ECDSA, negative cache, debug endpoints
- `lua-ssl-product-1.lua` - v1, single file, RSA only, kept for existing setups

## v2

### file layout

```
/etc/letsencrypt/$product_id/$sni_name.crt
/etc/letsencrypt/$product_id/$sni_name.key
# optional, only loaded with set_ecdsa(true)
/etc/letsencrypt/$product_id/$sni_name.ecdsa.crt
/etc/letsencrypt/$product_id/$sni_name.ecdsa.key
```

SNI is lowercased, so file names must be lowercase. The RSA pair is mandatory, ECDSA is optional per domain. With both loaded OpenSSL picks per handshake, RSA-only clients still get RSA.

### nginx config

Copy `v2/dynamic-ssl.lua` into a directory on `lua_package_path`. Full example: [v2/nginx-sample.conf](v2/nginx-sample.conf)

```
http {
    lua_package_path "/usr/local/openresty/nginx/conf/conf.d/?.lua;;";

    ## only if cache_method is lua_shared_dict in dynamic-ssl.lua
    # lua_shared_dict certs 16m;
    # lua_shared_dict certs_content 32m;

    init_by_lua_block {
        require "dynamic-ssl"
    }
}

server {
    listen 443 ssl;
    ssl_certificate     certs/dummy.crt;
    ssl_certificate_key certs/dummy.key;

    ## TLS 1.2 clients need ECDHE-ECDSA-* ciphers to get the ECDSA certificate
    # ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:...;

    ssl_certificate_by_lua_block {
        local dssl = require "dynamic-ssl"
        local lSSL = dssl:new("/etc/letsencrypt", "1", 600, false)
        lSSL:set_cert_process_method("opaque")
        lSSL:set_ecdsa(true)
        lSSL:exec()
    }
}
```

### API

| call | description |
|---|---|
| `dssl:new(dir_certs, product_id, cache_seconds, fallback)` | cert base dir, product id (subdir), cache TTL in seconds (`0` disables the cache), `fallback`: on error keep the default `ssl_certificate` instead of aborting the handshake |
| `set_cert_process_method("opaque" \| "der")` | default `der`; `opaque` is faster but only works with the `lrucache` cache method |
| `set_ecdsa(true)` | also load `<sni>.ecdsa.crt` / `<sni>.ecdsa.key` if present (default: off) |
| `set_certificate_path(crt, key[, ecdsa_crt, ecdsa_key])` | use fixed files instead of the SNI based lookup |
| `exec()` | do the lookup and set the certificate(s) |
| `handle_route()` | serve the `/dssl/` debug endpoints (see below) |

### cache

`cache_method` at the top of `dynamic-ssl.lua`:

- `lrucache` (default) - per worker, works with `opaque` and `der`
- `lua_shared_dict` - shared between workers, `der` only, needs the `lua_shared_dict` lines above

What this means in operation:

- renewed cert: picked up after `cache_seconds`, or immediately after `nginx -s reload` (`lrucache`) / `flush-cache-domain` (`lua_shared_dict`)
- new domain: if it was requested before the files existed, it stays rejected for up to `min(60, cache_seconds)` seconds (negative cache)
- missing cert with `fallback = false`: handshake is aborted, with `true` the default `ssl_certificate` is served
- logs: the same error is logged once per 5 minutes per worker, client noise (unknown/empty SNI) max 20 lines/min/worker, the rest is counted in `dynamic-ssl: suppressed N client log messages`

### debug endpoints

Restrict them to localhost:

```
location /dssl/ {
    allow 127.0.0.1;
    deny all;
    content_by_lua_block {
        local dssl = require "dynamic-ssl"
        local lSSL = dssl:new("/etc/letsencrypt", "1", 600, false)
        lSSL:set_cert_process_method("opaque")
        lSSL:handle_route()
    }
}
```

Use the same base dir, product id and process method as in `ssl_certificate_by_lua_block`, otherwise the cache keys will not match.

- `GET /dssl/get-cache-stats/` - cache method, capacity, free space, last sweep
- `GET /dssl/flush-cache/` - flush the whole cache
- `GET /dssl/flush-cache-domain/?domain=example.com` - drop one domain (RSA + ECDSA + negative entry)

With `lrucache` these only affect the worker that served the request, use `nginx -s reload` to clear all workers.

`ngx.ctx.DYNAMIC_SSL` holds the per-connection result (`method`, `cache_method`, `source`, `ecdsa`, `result`), see the `/ssl-debug-info/` location in the sample config.

## v1

Default configuration is in the lua script. And dir/file structure as an example:
/etc/letsencrypt/$product_id/$sni_name.crt
/etc/letsencrypt/$product_id/$sni_name.key

Ofc you can change these and do what you want with the script and use it as a baseline.

```
http {
...
    # global shared variables for the cert cache
    lua_shared_dict certs 16m;
    lua_shared_dict certs_content 32m;
...
}
...

# example server block
server {
        listen   1.2.3.4:443 ssl;
        http2 on;

        ssl_certificate /etc/nginx/ssl/dummy.crt;
        ssl_certificate_key /etc/nginx/ssl/dummy.key;
        ssl_certificate_by_lua_file /usr/local/openresty/nginx/conf/conf.d/lua-ssl-product-1.lua;

        ...
        ...
}
```
