test {
    _ = @import("framing/limits.zig");
    _ = @import("framing/batch.zig");
    _ = @import("framing/iterator.zig");
    _ = @import("compression/flate.zig");
    _ = @import("compression/algorithm.zig");
    _ = @import("crypto/spki.zig");
    _ = @import("crypto/ecdh.zig");
    _ = @import("crypto/session_crypto.zig");
    _ = @import("session/state.zig");
    _ = @import("session/connection.zig");
    _ = @import("transport/carrier.zig");
    _ = @import("auth/jwt.zig");
    _ = @import("auth/chain.zig");
    _ = @import("auth/moj_root.zig");
    _ = @import("resource_packs/manifest.zig");
    _ = @import("resource_packs/transfer.zig");
    _ = @import("compression/snappy.zig");
    _ = @import("auth/login.zig");
    _ = @import("compression/interop.zig");
}
