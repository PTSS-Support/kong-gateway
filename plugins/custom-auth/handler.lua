local http = require "resty.http"
local cjson = require "cjson"

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
  local cookie = headers["cookie"] or headers["Cookie"]
  ngx.log(ngx.WARN, "Full Cookie Header: " .. tostring(cookie))
  return cookie
end

local function validate_config(conf)
  if not conf or not conf.auth_url then
    ngx.log(ngx.ERR, "Missing required configuration: auth_url")
    return false
  end
  if not conf.refresh_token_cookie_name or not conf.access_token_cookie_name then
    ngx.log(ngx.ERR, "Missing required configuration: refresh token or access token name")
    return false
  end
  return true
end

local function should_skip_auth(conf)
  local path = ngx.var.request_uri
  ngx.log(ngx.ERR, "Current path: ", path)
  ngx.log(ngx.ERR, "Excluded paths: ", require("cjson").encode(conf.excluded_paths))

  for _, pattern in ipairs(conf.excluded_paths) do
    ngx.log(ngx.ERR, "Checking pattern: ", pattern)
    if ngx.re.match(path, pattern, "jo") then
      ngx.log(ngx.ERR, "Skipping auth for excluded path: ", path)
      return true
    end
  end
  return false
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
  ngx.log(ngx.DEBUG, "Cookie Header: " .. tostring(cookie_header))
  return {
    access_token = ngx.var.cookie_access_token or
            extract_cookie_value(cookie_header, conf.access_token_cookie_name),
    refresh_token = ngx.var.cookie_refresh_token or
            extract_cookie_value(cookie_header, conf.refresh_token_cookie_name),
    pin = ngx.var.cookie_pin or
            extract_cookie_value(cookie_header, "pin")
  }
end

local function handle_new_tokens(res)
  local set_cookie = res.headers["Set-Cookie"]

  -- If set_cookie is a table, take the first cookie
  if type(set_cookie) == "table" then
    ngx.log(ngx.DEBUG, "Multiple Set-Cookie headers found:")
    for i, cookie in ipairs(set_cookie) do
      ngx.log(ngx.DEBUG, "Cookie " .. i .. ": " .. tostring(cookie))
    end
    set_cookie = table.concat(set_cookie, "; ")
  end

  local new_access_token = set_cookie and
          extract_cookie_value(set_cookie, conf.access_token_cookie_name)

  local new_refresh_token = set_cookie and
          extract_cookie_value(set_cookie, conf.refresh_token_cookie_name)

  if not new_access_token then
    return nil, "Failed to generate new access token"
  end

  if not new_refresh_token then
    ngx.log(ngx.WARN, "No new refresh token received from auth service")
  end

  return new_access_token, new_refresh_token
end

-- Flow Handlers
local function handle_pin_validation(conf, tokens)
  if not tokens.pin or not tokens.refresh_token then
    ngx.log(ngx.INFO, "No PIN or refresh token found in request")
    return nil, 401, "Authentication required"
  end

  local cookie_header = string.format("%s=%s; pin=%s",
          conf.refresh_token_cookie_name,
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

  local new_access_token, new_refresh_token = handle_new_tokens(res)
  if not new_access_token then
    return nil, 500, err
  end

  -- Handle multiple Set-Cookie headers
  local set_cookie = res.headers["Set-Cookie"]
  if type(set_cookie) == "table" then
    -- Set each cookie as a separate header
    for _, cookie in ipairs(set_cookie) do
      kong.response.add_header("Set-Cookie", cookie)
    end
  else
    -- Single cookie case
    kong.response.set_header("Set-Cookie", set_cookie)
  end
  kong.service.request.set_header("Cookie", conf.access_token_cookie_name .. "=" .. new_access_token ..
          "; " .. conf.refresh_token_cookie_name .. "=" .. (new_refresh_token or ""))
  return true
end

local function handle_token_validation(conf, tokens)
  local res = make_auth_request(conf.auth_url .. "/auth/validate", {
    ["Content-Type"] = "application/json",
    ["Cookie"] = conf.access_token_cookie_name .. "=" .. tokens.access_token
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
    local new_access_token = extract_cookie_value(res.headers["Set-Cookie"], conf.access_token_cookie_name)
    if new_access_token then
      token_to_cache = new_access_token
      kong.response.set_header("Set-Cookie", res.headers["Set-Cookie"])
    end
  end

  kong.service.request.set_header("Cookie", conf.access_token_cookie_name .. "=" .. token_to_cache)
  return true
end

function CustomAuth:access(conf)
  ngx.log(ngx.DEBUG, "Starting CustomAuth access function")

  if not validate_config(conf) then
    return kong.response.exit(500, { message = "Plugin configuration error" })
  end

  if should_skip_auth(conf) then
    return
  end

  local cookie_header = get_cookie_header()
  local tokens = extract_tokens(cookie_header)

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