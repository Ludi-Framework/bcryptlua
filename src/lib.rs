use mlua::prelude::*;

/// bcrypt operates on at most 72 bytes of password; anything past that
/// never enters the hash. Hashing silently-truncated input would make
/// long passwords with a common 72-byte prefix collide, so we refuse it
/// instead (the Lua wrapper rejects it first with a caller-located error;
/// this is the safety net).
const MAX_PASSWORD_BYTES: usize = 72;

const MIN_COST: u32 = 4;
const MAX_COST: u32 = 31;

fn hash(_: &Lua, (password, cost): (LuaString, u32)) -> LuaResult<String> {
    let bytes = password.as_bytes();
    if bytes.len() > MAX_PASSWORD_BYTES {
        return Err(LuaError::runtime(format!(
            "Password exceeds bcrypt's 72-byte limit ({} bytes)",
            bytes.len()
        )));
    }
    if !(MIN_COST..=MAX_COST).contains(&cost) {
        return Err(LuaError::runtime(format!(
            "Cost must be between {MIN_COST} and {MAX_COST}, got {cost}"
        )));
    }
    bcrypt::hash(&*bytes, cost).map_err(|err| LuaError::runtime(err.to_string()))
}

/// Wrong password and malformed/unsupported hash both come back `false`:
/// distinguishing them would let a caller leak which accounts hold a
/// valid hash, and every reference implementation (OpenBSD, node.bcrypt)
/// collapses the two as well. The comparison inside `bcrypt::verify` is
/// constant-time (`subtle`).
fn verify(_: &Lua, (password, hash): (LuaString, LuaString)) -> LuaResult<bool> {
    let Ok(hash) = hash.to_str() else {
        return Ok(false);
    };
    Ok(bcrypt::verify(&*password.as_bytes(), &hash).unwrap_or(false))
}

#[mlua::lua_module]
fn bcryptlua_core(lua: &Lua) -> LuaResult<LuaTable> {
    let exports = lua.create_table()?;
    exports.set("hash", lua.create_function(hash)?)?;
    exports.set("verify", lua.create_function(verify)?)?;
    Ok(exports)
}
