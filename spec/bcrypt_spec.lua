local bcrypt = require("bcryptlua")

-- Cost 4 (the minimum) keeps the suite fast; correctness does not
-- depend on the cost.
local FAST = 4

describe("bcrypt.hash", function()
    it("returns a 60-character $2b$ hash", function()
        local hash = bcrypt.hash("secret", FAST)
        assert.equal(60, #hash)
        assert.truthy(hash:match("^%$2b%$04%$"))
    end)

    it("salts every hash: same password, different hashes", function()
        assert.not_equal(bcrypt.hash("secret", FAST), bcrypt.hash("secret", FAST))
    end)

    it("defaults to cost 12", function()
        assert.equal(12, bcrypt.cost(bcrypt.hash("secret")))
    end)

    it("accepts the empty password", function()
        assert.is_true(bcrypt.verify("", bcrypt.hash("", FAST)))
    end)

    it("accepts a password of exactly 72 bytes", function()
        local password = ("x"):rep(72)
        assert.is_true(bcrypt.verify(password, bcrypt.hash(password, FAST)))
    end)

    it("rejects a password over 72 bytes", function()
        assert.error_matches(function()
            bcrypt.hash(("x"):rep(73), FAST)
        end, "72%-byte limit")
    end)

    it("hashes embedded NUL bytes instead of truncating at them", function()
        local hash = bcrypt.hash("abc\0def", FAST)
        assert.is_true(bcrypt.verify("abc\0def", hash))
        assert.is_false(bcrypt.verify("abc", hash))
    end)

    it("is 8-bit clean (high bytes)", function()
        local password = "\xff\xa3\x34\x35"
        assert.is_true(bcrypt.verify(password, bcrypt.hash(password, FAST)))
    end)

    it("round-trips multibyte UTF-8", function()
        local password = "ππππππππ"
        assert.is_true(bcrypt.verify(password, bcrypt.hash(password, FAST)))
    end)

    it("rejects cost below 4 and above 31", function()
        assert.error_matches(function()
            bcrypt.hash("x", 3)
        end, "between 4 and 31")
        assert.error_matches(function()
            bcrypt.hash("x", 32)
        end, "between 4 and 31")
    end)

    it("rejects a non-integer cost", function()
        assert.error_matches(function()
            bcrypt.hash("x", 4.5)
        end, "integer")
        assert.error_matches(function()
            bcrypt.hash("x", "12")
        end, "integer")
    end)

    it("rejects a non-string password", function()
        assert.error_matches(function()
            bcrypt.hash(42, FAST)
        end, "string")
        assert.error_matches(function()
            bcrypt.hash(nil, FAST)
        end, "string")
    end)
end)

describe("bcrypt.verify", function()
    -- Known-answer vectors from the jBCrypt/OpenBSD suite (also used by
    -- bcrypt.net and node.bcrypt.js), plus PHP password_hash ($2y$) and
    -- Laravel outputs, to prove cross-implementation compatibility.
    local vectors = {
        { "", "$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s." },
        { "a", "$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe" },
        { "abc", "$2a$10$WvvTPHKwdBJ3uk0Z37EMR.hLA2W6N9AEBhEgrAOljy2Ae5MtaSIUi" },
        { "abcdefghijklmnopqrstuvwxyz", "$2a$12$D4G5f18o7aMMfwasBL7GpuQWuP3pkrZrOAnqP.bmezbMng.QwJ/pG" },
        { "~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$06$fPIsBO8qRqkjj273rfaOI.HtSV9jLDpTbZn782DC6/t7qT67P6FfO" },
        { "password", "$2a$12$oH4q4SYhvsTMLk1Ch6aQ1.7kFpyMNnrLepschA0IXS5zoOCdEE332" },
        { "WjswE$v?(n2/", "$2y$12$Y7LETq.zS/D1DqYlh4I6beRvX8nF/VEJKnjOLGz6d9.jJKleH.d0a" },
    }

    it("accepts known hashes from other implementations ($2a$, $2y$)", function()
        for _, vector in ipairs(vectors) do
            local password, hash = vector[1], vector[2]
            assert.is_true(bcrypt.verify(password, hash), ("vector failed: %q"):format(password))
        end
    end)

    it("rejects the wrong password against known hashes", function()
        for _, vector in ipairs(vectors) do
            assert.is_false(bcrypt.verify("wrong-password", vector[2]))
        end
    end)

    it("returns false for malformed hashes instead of raising", function()
        assert.is_false(bcrypt.verify("secret", ""))
        assert.is_false(bcrypt.verify("secret", ":"))
        assert.is_false(bcrypt.verify("secret", "not a hash"))
        assert.is_false(bcrypt.verify("secret", "$2z$04$" .. ("x"):rep(53)))
        assert.is_false(bcrypt.verify("secret", "$2b$04$too-short"))
    end)

    it("rejects a non-string password or hash", function()
        assert.error_matches(function()
            bcrypt.verify(42, "hash")
        end, "string")
        assert.error_matches(function()
            bcrypt.verify("secret", 42)
        end, "string")
    end)
end)

describe("bcrypt.cost", function()
    it("extracts the cost from a hash", function()
        assert.equal(4, bcrypt.cost(bcrypt.hash("secret", FAST)))
        assert.equal(6, bcrypt.cost("$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s."))
        assert.equal(12, bcrypt.cost("$2y$12$Y7LETq.zS/D1DqYlh4I6beRvX8nF/VEJKnjOLGz6d9.jJKleH.d0a"))
    end)

    it("returns nil plus an error for malformed hashes", function()
        local cost, err = bcrypt.cost("not a hash")
        assert.is_nil(cost)
        assert.equal("Malformed bcrypt hash", err)
    end)

    it("rejects a non-string hash", function()
        assert.error_matches(function()
            bcrypt.cost(nil)
        end, "string")
    end)
end)
