pub const CompressionAlgorithm = enum { none, deflate, snappy };

pub const SessionFeatures = struct {
    uses_request_network_settings: bool = true,
    supports_deflate: bool = true,
    supports_snappy: bool = true,
    initial_algorithm: CompressionAlgorithm = .none,
    compression_mode: enum { absent, implicit, marked } = .marked,
    login_flow: enum { certificate_chain, oidc } = .oidc,
    resource_pack_flow: enum { classic, with_validation } = .with_validation,

    pub fn validate(self: SessionFeatures) error{UnsupportedProtocol}!void {
        if (self.compression_mode == .marked and !self.supports_deflate and !self.supports_snappy) return error.UnsupportedProtocol;
        if (self.compression_mode == .implicit and self.initial_algorithm == .none) return error.UnsupportedProtocol;
        if (self.compression_mode == .absent and self.initial_algorithm != .none) return error.UnsupportedProtocol;
        if (self.initial_algorithm == .deflate and !self.supports_deflate) return error.UnsupportedProtocol;
        if (self.initial_algorithm == .snappy and !self.supports_snappy) return error.UnsupportedProtocol;
    }
};
