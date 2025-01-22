local typedefs = require "kong.db.schema.typedefs"
local cjson = require "cjson"

-- Get environment variables and parse JSON
local excluded_paths = os.getenv("KONG_EXCLUDED_PATHS")
local default_excluded_paths = {}

if excluded_paths then
    local success, paths = pcall(cjson.decode, excluded_paths)
    if success then
        default_excluded_paths = paths
    end
end

return {
    name = "custom-auth",
    fields = {
        { consumer = typedefs.no_consumer },
        { protocols = typedefs.protocols_http },
        { config = {
            type = "record",
            fields = {
                { auth_url = {
                    type = "string",
                    default = os.getenv("KONG_AUTH_URL") or "http://host.docker.internal:8081"
                }},
                { access_token_cookie_name = {
                    type = "string",
                    default = os.getenv("ACCESS_TOKEN_COOKIE_NAME") or "access_token"
                }},
                { refresh_token_cookie_name = {
                    type = "string",
                    default = os.getenv("REFRESH_TOKEN_COOKIE_NAME") or "refresh_token"
                }},
                { excluded_paths = {
                    type = "array",
                    elements = { type = "string" },
                    default = default_excluded_paths
                }
                },
                { excluded_methods = {
                    type = "array",
                    elements = {
                        type = "string",
                        one_of = { "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD" }
                    },
                    default = { "OPTIONS" }
                }
                }
            }
        }
        }
    }
}