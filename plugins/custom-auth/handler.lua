local http = require "resty.http"
local cjson = require "cjson"

local CustomAuth = {
  PRIORITY = 1000,
  VERSION = "1.0.0",
}

function CustomAuth:access(conf)
  -- Log that we entered the function
  ngx.log(ngx.DEBUG, "Starting CustomAuth access function")
  ngx.log(ngx.DEBUG, "conf dump: ", require("cjson").encode(conf))


  -- Log all headers
  local headers = ngx.req.get_headers()
  ngx.log(ngx.DEBUG, "All headers: ", cjson.encode(headers))

  -- Try multiple ways to get cookies
  local cookie_header = headers["cookie"] or headers["Cookie"]
  ngx.log(ngx.DEBUG, "Cookie header: ", cookie_header)

  local access_token = ngx.var.cookie_access_token
  ngx.log(ngx.DEBUG, "Access token from ngx.var: ", access_token)

  -- Try parsing cookie header manually
  if cookie_header then
    local from_cookie = string.match(cookie_header, "access_token=([^;]+)")
    ngx.log(ngx.DEBUG, "Access token from manual parse: ", from_cookie)
    access_token = access_token or from_cookie
  end

  if not access_token or access_token == "" then
    ngx.log(ngx.INFO, "No access token found, checking for PIN")

    -- Get PIN from cookie
    local pin = ngx.var.cookie_pin
    if cookie_header then
      pin = pin or string.match(cookie_header, "pin=([^;]+)")
    end

    if not pin or pin == "" then
      ngx.log(ngx.ERR, "No PIN found in request")
      return kong.response.exit(401, { message = "Authentication required" })
    end
    local refresh_token = ngx.var.cookie_refresh_token
    if cookie_header then
      refresh_token = refresh_token or string.match(cookie_header, "refresh_token=([^;]+)")
    end

    if not refresh_token or refresh_token == "" then
      ngx.log(ngx.ERR, "No refresh token found in request")
      return kong.response.exit(401, { message = "Authentication required" })
    end

    -- Create HTTP client for PIN validation
    local httpc = http.new()

    if not conf or not conf.config or not conf.config.auth_url then
      ngx.log(ngx.ERR, "Missing required configuration: auth_url")
      return kong.response.exit(500, { message = "Plugin configuration error" })
    end

    -- Send request to authentication service for PIN validation
    local res, err = httpc:request_uri(conf.config.auth_url .. "/validate-pin", {
      method = "POST",
      headers = {
        ["Content-Type"] = "application/json",
        ["Cookie"] = "refresh_token=" .. refresh_token .. "; pin=" .. pin
      }
    })

    if not res then
      ngx.log(ngx.ERR, "Failed to call auth service: ", err)
      return kong.response.exit(500, { message = "Internal server error" })
    end

    ngx.log(ngx.INFO, "PIN validation response status: ", res.status)

    if res.status ~= 200 then
      return kong.response.exit(res.status, { message = "Invalid PIN or refresh token" })
    end

    -- Kong will automatically forward these cookies to the client
    access_token = res.headers["Set-Cookie"] and string.match(res.headers["Set-Cookie"], "access_token=([^;]+)")

    if not access_token then
      ngx.log(ngx.ERR, "No access token received from auth service")
      return kong.response.exit(500, { message = "Failed to generate new access token" })
    end
    kong.service.request.set_header("Cookie", "access_token=" .. access_token)
    return
  end

  ngx.log(ngx.INFO, "Found access token, proceeding with verification")

  local httpc = http.new()

  if not conf or not conf.config or not conf.config.auth_url then
    ngx.log(ngx.ERR, "Missing required configuration: auth_url")
    return kong.response.exit(500, { message = "Plugin configuration error" })
  end

  -- Send request to authentication service using configured URL
  local res, err = httpc:request_uri(conf.config.auth_url, {
    method = "POST",
    headers = {
      ["Content-Type"] = "application/json",
      ["Cookie"] = "access_token=" .. access_token
    }
  })

  if not res then
    ngx.log(ngx.ERR, "Failed to call auth service: ", err)
    return kong.response.exit(500, { message = "Internal server error" })
  end

  ngx.log(ngx.ERR, "Auth service response status: ", res.status)

  -- Handle authentication service response
  if res.status == 200 then
    -- Forward the access token cookie to upstream service
    kong.service.request.set_header("Cookie", "access_token=" .. access_token)
    return
  elseif res.status == 401 or res.status == 400 then
    return kong.response.exit(res.status, { message = "Invalid or expired token" })
  else
    return kong.response.exit(500, { message = "Authentication service error" })
  end
end

return CustomAuth