test {
    _ = @import("session/handshake.zig");
    _ = @import("session/framing.zig");
    _ = @import("session/compression.zig");
    _ = @import("session/crypto.zig");
    _ = @import("session/memory.zig");
    _ = @import("session/codec.zig");
    _ = @import("session/pool.zig");
    _ = @import("session/concurrency.zig");

    _ = @import("auth/jwt.zig");
    _ = @import("auth/chain.zig");
    _ = @import("auth/wire.zig");
    _ = @import("auth/jwks.zig");

    _ = @import("compression/codecs.zig");
    _ = @import("compression/interop.zig");

    _ = @import("resource_packs/negotiation.zig");
    _ = @import("resource_packs/transfer.zig");
}
