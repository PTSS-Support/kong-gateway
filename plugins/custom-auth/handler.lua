local http = require "resty.http"
local cjson = require "cjson"
local ngx_shared = ngx.shared
local cache

local CustomAuth = {
  PRIORITY = 1000,
  VERSION = "1.0.0",
}

-- Helper Functions
local function extract_cookie_value(cookie_header, cookie_name)
  if not cookie_header then return nil end
  return string.match(cookie_header, cookie_name .. "=([^;]+)")
end

local function get_cookie_header()
  local headers = ngx.req.get_headers()
  return headers["cookie"] or headers["Cookie"]
end

local function validate_config(conf)
  if not conf or not conf.auth_url then
    ngx.log(ngx.ERR, "Missing required configuration: auth_url")
    return false
  end
  return true
end

-- In-memory cache
local CACHE_TTL = 300

local function cache_token(token)
  local success, err, forcible = cache:set(token, true, CACHE_TTL)
  if not success then
    ngx.log(ngx.ERR, "Failed to cache token: ", err)
  elseif forcible then
    ngx.log(ngx.WARN, "Forced LRU eviction while caching token")
  end
end

local function is_token_cached(token)
  return cache:get(token) ~= nil
end

-- HTTP Client Management
local function make_auth_request(url, headers)
  local httpc = http.new()
  local res, err = httpc:request_uri(url, {
    method = "POST",
    headers = headers,
    keepalive_timeout = 60,
    keepalive_pool = 10
  })

  if not res then
    ngx.log(ngx.ERR, "Failed to call auth service: ", err)
    ngx.log(ngx.ERR, "URL attempted: ", url)
    return nil, "Internal server error"
  end
  ngx.log(ngx.DEBUG, "Auth service response status: ", res.status)

  return res
end

-- Token Management
local function extract_tokens(cookie_header)
  return {
    access_token = ngx.var.cookie_access_token or
            extract_cookie_value(cookie_header, "access_token"),
    refresh_token = ngx.var.cookie_refresh_token or
            extract_cookie_value(cookie_header, "refresh_token"),
    pin = ngx.var.cookie_pin or
            extract_cookie_value(cookie_header, "pin")
  }
end

local function handle_new_tokens(res)
  local set_cookie = res.headers["Set-Cookie"]

  -- If set_cookie is a table, take the first cookie
  if type(set_cookie) == "table" then
    set_cookie = set_cookie[1]
  end

  local new_access_token = set_cookie and
          extract_cookie_value(set_cookie, "access_token")

  local new_refresh_token = set_cookie and
          extract_cookie_value(set_cookie, "refresh_token")

  if not new_access_token then
    return nil, "Failed to generate new access token"
  end

  if not new_refresh_token then
    ngx.log(ngx.WARN, "No new refresh token received from auth service")
  end

  return new_access_token
end

-- Flow Handlers
local function handle_pin_validation(conf, tokens)
  if not tokens.pin or not tokens.refresh_token then
    ngx.log(ngx.INFO, "No PIN or refresh token found in request")
    return nil, 401, "Authentication required"
  end

  local cookie_header = string.format("refresh_token=%s; pin=%s",
          tostring(tokens.refresh_token),
          tostring(tokens.pin))

  local res = make_auth_request(conf.auth_url .. "/auth/login/pin", {
    ["Content-Type"] = "application/json",
    ["Cookie"] = cookie_header
  })

  if not res then
    return nil, 500, "Internal server error"
  end

  ngx.log(ngx.INFO, "PIN validation response status: ", res.status)

  if res.status ~= 204 then
    return nil, res.status, cjson.decode(res.body)
  end

  local new_access_token, err = handle_new_tokens(res)
  if not new_access_token then
    return nil, 500, err
  end

  cache_token(new_access_token)

  -- Handle multiple Set-Cookie headers
  local set_cookie = res.headers["Set-Cookie"]
  if type(set_cookie) == "table" then
    set_cookie = table.concat(set_cookie, "; ")
  end

  kong.response.set_header("Set-Cookie", set_cookie)
  kong.service.request.set_header("Cookie", "access_token=" .. new_access_token)
  return true
end

local function handle_token_validation(conf, tokens)
  local res = make_auth_request(conf.auth_url .. "/auth/validate", {
    ["Content-Type"] = "application/json",
    ["Cookie"] = "access_token=" .. tokens.access_token
  })

  if not res then
    return nil, 500, "Internal server error"
  end

  ngx.log(ngx.INFO, "Token validation response status: ", res.status)

  if res.status ~= 204 then
    return nil, res.status, cjson.decode(res.body)
  end

  -- Handle token refresh if provided
  local token_to_cache = tokens.access_token
  if res.headers["Set-Cookie"] then
    local new_access_token = extract_cookie_value(res.headers["Set-Cookie"], "access_token")
    if new_access_token then
      token_to_cache = new_access_token
      kong.response.set_header("Set-Cookie", res.headers["Set-Cookie"])
    end
  end

  cache_token(token_to_cache)
  kong.service.request.set_header("Cookie", "access_token=" .. token_to_cache)
  return true
end

-- Core Plugin Functions
function CustomAuth:init_worker()
  -- Initialize the shared dictionary reference
  cache = ngx_shared.tokens
  if not cache then
    ngx.log(ngx.ERR, "Failed to initialize shared dictionary 'tokens'")
  end
end

function CustomAuth:access(conf)
  ngx.log(ngx.DEBUG, "Starting CustomAuth access function")

  if not cache then
    ngx.log(ngx.ERR, "Shared dictionary not initialized")
    return kong.response.exit(500, { message = "Internal server error" })
  end

  if not validate_config(conf) then
    return kong.response.exit(500, { message = "Plugin configuration error" })
  end

  local cookie_header = get_cookie_header()
  local tokens = extract_tokens(cookie_header)

  -- Check cache first
  if tokens.access_token and is_token_cached(tokens.access_token) then
    ngx.log(ngx.INFO, "Token found in cache, skipping validation")
    kong.service.request.set_header("Cookie", "access_token=" .. tokens.access_token)
    return
  end

  -- Handle authentication flows
  local success, status, message
  if not tokens.access_token or tokens.access_token == "" then
    ngx.log(ngx.INFO, "No access token found, attempting PIN flow")
    success, status, message = handle_pin_validation(conf, tokens)
  else
    ngx.log(ngx.INFO, "Found access token, proceeding with verification")
    success, status, message = handle_token_validation(conf, tokens)
  end

  if not success then
    return kong.response.exit(status, { message = message })
  end
end

return CustomAuth