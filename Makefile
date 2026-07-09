# Local development without luarocks. Builds the native module for the
# chosen Lua and symlinks it next to the Lua sources so require() finds it.
#
#   make dev              # build for Lua 5.5
#   make dev LUA=lua54    # build for Lua 5.4
#   make dev LUA=luajit   # build for LuaJIT
#   make test             # build + busted specs

LUA ?= lua55

dev:
	cargo build --release --features $(LUA)
	ln -sf target/release/libbcryptlua_core.so bcryptlua_core.so

# Lua specs need busted (luarocks install busted). `luarocks test` works too.
test: dev
	busted

# Format Rust (rustfmt) and Lua (stylua) sources in place.
fmt:
	cargo fmt
	stylua bcryptlua.lua spec/

# Verify formatting without writing; fails if anything is out of style.
fmt-check:
	cargo fmt --check
	stylua --check bcryptlua.lua spec/

.PHONY: dev test fmt fmt-check
