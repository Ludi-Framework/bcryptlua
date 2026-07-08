# bcryptlua

bcrypt password hashing for Lua, powered by Rust.

```lua
local bcrypt = require("bcryptlua")

local hash = bcrypt.hash("correct horse battery staple")
bcrypt.verify("correct horse battery staple", hash)  -- true
bcrypt.verify("Tr0ub4dor&3", hash)                   -- false
```

Three functions, safe defaults, no C-string pitfalls. Hashes are
standard 60-character `$2b$` modular-crypt strings, interchangeable
with every other bcrypt implementation — and `verify` accepts `$2a$`,
`$2x$` and `$2y$` hashes too, so password databases written by PHP
(`password_hash`), Python (passlib) or Node keep working as-is.

## Installation

```bash
luarocks install bcryptlua
```

Works on Lua 5.1+ and LuaJIT. Building from source requires
[Rust](https://rustup.rs); prebuilt binary rocks need nothing.

## API

### `bcrypt.hash(password, cost?) → hash`

Hashes a password with a freshly generated random salt (from the OS
CSPRNG) and returns the 60-character hash string to store.

`cost` is the log2 of the number of rounds, `4`–`31`, default `12`.
Each `+1` doubles the work: pick the highest your login latency budget
tolerates.

```lua
bcrypt.hash("secret")      -- $2b$12$...
bcrypt.hash("secret", 14)  -- slower, stronger
```

Raises an error when the password is not a string or exceeds
**72 bytes** — bcrypt never reads past the 72nd byte, and silently
truncating would make long passwords sharing a prefix collide.
Enforce a length limit in your signup form, or hash a digest of the
password instead.

### `bcrypt.verify(password, hash) → boolean`

Checks a password against a stored hash. The comparison is
constant-time. A malformed or unsupported hash returns `false`,
deliberately indistinguishable from a wrong password.

### `bcrypt.cost(hash) → cost | nil, err`

Extracts the cost from a stored hash — the rehash-on-login pattern for
upgrading old hashes as users authenticate:

```lua
if bcrypt.verify(password, stored) then
    if bcrypt.cost(stored) < 12 then
        save(bcrypt.hash(password, 12))
    end
    -- logged in
end
```

Returns `nil, "Malformed bcrypt hash"` when the string cannot be
parsed.

## Design notes

- **Rust core** ([`bcrypt`](https://crates.io/crates/bcrypt) crate via
  [mlua](https://github.com/mlua-rs/mlua)): salts come from the OS
  CSPRNG (`getrandom`), verification compares in constant time, and
  passwords are handled as length-aware byte strings — embedded `NUL`
  bytes are hashed, not truncated at, unlike C bindings built on
  `strlen`.
- **Errors are loud, comparisons are quiet.** Invalid arguments to
  `hash` (bad cost, oversized password) raise, because storing a
  weaker hash than intended is a bug. `verify` never raises on bad
  hash input, because at login time "malformed hash" and "wrong
  password" must be the same answer.
- **Cost is never clamped.** Some libraries silently round an
  out-of-range cost to the nearest bound; a typo'd `bcrypt.hash(pw, 2)`
  quietly producing a cost-4 hash is a security downgrade, so it
  raises instead.

## Development

Requires Rust, a Lua (5.1+ or LuaJIT — 5.5 recommended) with headers,
and [busted](https://lunarmodules.github.io/busted/) for the specs.

```bash
make dev              # build the native module for Lua 5.5
make dev LUA=lua54    # ... or for Lua 5.4
make dev LUA=luajit   # ... or for LuaJIT
make test             # build + busted
```

The spec suite includes known-answer vectors shared with jBCrypt,
node.bcrypt.js and bcrypt.net, plus PHP `password_hash` output, to
guarantee cross-implementation compatibility.

## License

[MIT](LICENSE)
