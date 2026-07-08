--- bcrypt password hashing, powered by Rust.
---
--- Hashes are standard `$2b$` modular-crypt strings, 60 characters,
--- interchangeable with every other bcrypt implementation. `verify`
--- also accepts `$2a$`, `$2x$` and `$2y$` hashes (PHP, passlib, older
--- libraries), so existing password databases keep working.

local core = require("bcryptlua_core")

local bcrypt = {}

local DEFAULT_COST = 12
local MIN_COST, MAX_COST = 4, 31

-- bcrypt only feeds the first 72 bytes of the password into the hash.
-- Truncating silently would make long passwords sharing a 72-byte
-- prefix collide, so oversized input is an error the caller must
-- handle (validate the length up front, or hash a digest instead).
local MAX_PASSWORD_BYTES = 72

--- Hashes a password with a freshly generated random salt.
---@param password string up to 72 bytes
---@param cost? integer log2 of the number of rounds, 4..31 (default 12)
---@return string hash 60-character `$2b$` hash
function bcrypt.hash(password, cost)
    if type(password) ~= "string" then
        error("Password must be a string", 2)
    end
    if #password > MAX_PASSWORD_BYTES then
        error(("Password exceeds bcrypt's 72-byte limit (%d bytes)")
            :format(#password), 2)
    end
    if cost == nil then
        cost = DEFAULT_COST
    elseif type(cost) ~= "number" or cost % 1 ~= 0 then
        error("Cost must be an integer", 2)
    elseif cost < MIN_COST or cost > MAX_COST then
        error(("Cost must be between %d and %d, got %d")
            :format(MIN_COST, MAX_COST, cost), 2)
    end
    return core.hash(password, cost)
end

--- Checks a password against a stored hash. Constant-time comparison.
--- A malformed hash returns `false`, indistinguishable from a wrong
--- password on purpose.
---@param password string
---@param hash string
---@return boolean
function bcrypt.verify(password, hash)
    if type(password) ~= "string" then
        error("Password must be a string", 2)
    end
    if type(hash) ~= "string" then
        error("Hash must be a string", 2)
    end
    return core.verify(password, hash)
end

--- Extracts the cost from a stored hash — the rehash-on-login check:
--- `if bcrypt.cost(stored) < 12 then rehash() end`.
---@param hash string
---@return integer|nil cost
---@return string? err "Malformed bcrypt hash" when it cannot be parsed
function bcrypt.cost(hash)
    if type(hash) ~= "string" then
        error("Hash must be a string", 2)
    end
    local cost = hash:match("^%$2[abxy]%$(%d%d)%$[./A-Za-z0-9]+$")
    if not cost or #hash ~= 60 then
        return nil, "Malformed bcrypt hash"
    end
    return tonumber(cost)
end

return bcrypt
