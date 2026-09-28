const spki = @import("../crypto/spki.zig");
/// Mojang's legacy chain root, as pinned by gophertunnel.
pub const encoded = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAECRXueJeTDqNRRgJi/vlRufByu/2G0i2Ebt6YMar5QX/R0DIIyrJMcUpruK4QveTfJSTp3Shlq4Gk34cD/4GUWwkv0DVuzeuB+tXija7HBxii03NHDbPAD0AKnLr2wdAp";
pub fn key() spki.Ecdsa.PublicKey {
    return spki.fromBase64(encoded) catch unreachable;
}
