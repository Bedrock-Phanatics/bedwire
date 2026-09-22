//! bedrock session layer
//!
//! sits between transport (raknet, nethernet) and packet codecs.
//! handles 0xfe framing, compression, encryption, auth and handshake state.

const std = @import("std");

pub const Limits = @import("limits.zig").Limits;
pub const errors = @import("errors.zig");

pub const protocol = struct {
    pub const PacketKind = @import("protocol/kind.zig").PacketKind;
    pub const Descriptor = @import("protocol/descriptor.zig").Descriptor;
    pub const Entry = @import("protocol/descriptor.zig").Entry;
    pub const PacketId = @import("protocol/descriptor.zig").PacketId;
    pub const build = @import("protocol/descriptor.zig").build;

    pub const SessionFeatures = @import("protocol/features.zig").SessionFeatures;
    pub const Algorithm = @import("protocol/features.zig").Algorithm;
    pub const CompressionMode = @import("protocol/features.zig").CompressionMode;
    pub const ConnectionRequestFormat = @import("protocol/features.zig").ConnectionRequestFormat;
    pub const LoginFlow = @import("protocol/features.zig").LoginFlow;
    pub const ResourcePackFlow = @import("protocol/features.zig").ResourcePackFlow;
    pub const EncryptionPolicy = @import("protocol/features.zig").EncryptionPolicy;
    pub const forVersion = @import("protocol/features.zig").forVersion;

    pub const describe = @import("protocol/registry.zig").describe;
    pub const describeWith = @import("protocol/registry.zig").describeWith;
};

pub const Session = @import("session/session.zig").Session;
pub const Packet = @import("session/session.zig").Packet;
pub const Packets = @import("session/session.zig").Packets;
pub const SessionOptions = @import("session/session.zig").Options;
pub const Frame = @import("session/session.zig").Frame;
pub const BufferPool = @import("session/session.zig").BufferPool;
pub const PoolConfig = @import("session/session.zig").PoolConfig;
pub const Role = @import("session/state.zig").Role;
pub const State = @import("session/state.zig").State;
pub const PacketKind = protocol.PacketKind;
pub const Descriptor = protocol.Descriptor;

pub const framing = struct {
    pub const batch = @import("framing/batch.zig");
    pub const varint = @import("framing/varint.zig");
};

pub const compression = struct {
    pub const Compression = @import("compression/algorithm.zig").Compression;
    pub const Workspace = @import("compression/algorithm.zig").Workspace;
    pub const Algorithm = protocol.Algorithm;
    pub const flate = @import("compression/flate.zig");
    pub const snappy = @import("compression/snappy.zig");
};

pub const crypto = struct {
    pub const spki = @import("crypto/spki.zig");
    pub const ecdh = @import("crypto/ecdh.zig");
    pub const SessionCrypto = @import("crypto/session_crypto.zig").SessionCrypto;
};

pub const auth = struct {
    pub const wire = @import("auth/wire.zig");
    pub const jwt = @import("auth/jwt.zig");
    pub const jwks = @import("auth/jwks.zig");
    pub const login = @import("auth/login.zig");
    pub const identity = @import("auth/identity.zig");
    pub const oidc = @import("auth/oidc.zig");
    pub const chain = @import("auth/chain.zig");
    pub const Identity = @import("auth/identity.zig").Identity;
    pub const ChainPolicy = @import("auth/chain.zig").ChainPolicy;
    pub const OidcPolicy = @import("auth/oidc.zig").OidcPolicy;
    pub const verifyChain = @import("auth/chain.zig").verifyChain;
    pub const verifyOidc = @import("auth/oidc.zig").verifyOidc;
    pub const moj_root = @import("auth/moj_root.zig");
};

pub const resource_packs = struct {
    pub const Negotiation = @import("resource_packs/negotiation.zig").Negotiation;
    pub const Offer = @import("resource_packs/negotiation.zig").Offer;
    pub const Response = @import("resource_packs/negotiation.zig").Response;
    pub const Phase = @import("resource_packs/negotiation.zig").Phase;
    pub const Transfer = @import("resource_packs/transfer.zig").Transfer;
    pub const Metadata = @import("resource_packs/transfer.zig").Metadata;
    pub const Chunk = @import("resource_packs/transfer.zig").Chunk;
    pub const Request = @import("resource_packs/transfer.zig").Request;
    pub const serve = @import("resource_packs/transfer.zig").serve;
};

/// Optional, comptime-generic transport bindings. Neither imports its transport,
/// so depending on Bedwire never pulls in RakNet or libdatachannel.
pub const transport = struct {
    pub const RakNet = @import("transport/raknet.zig").RakNet;
    pub const NetherNet = @import("transport/nethernet.zig").NetherNet;
};

test {
    std.testing.refAllDecls(@This());

    _ = @import("limits.zig");
    _ = @import("protocol/kind.zig");
    _ = @import("protocol/features.zig");
    _ = @import("protocol/descriptor.zig");
    _ = @import("protocol/registry.zig");
    _ = @import("framing/varint.zig");
    _ = @import("framing/batch.zig");
    _ = @import("session/state.zig");
    _ = @import("session/pool.zig");
    _ = @import("session/session.zig");
    _ = @import("auth/wire.zig");
    _ = @import("auth/jwks.zig");
    _ = @import("auth/identity.zig");
    _ = @import("auth/oidc.zig");
    _ = @import("transport/raknet.zig");
    _ = @import("transport/nethernet.zig");
}
