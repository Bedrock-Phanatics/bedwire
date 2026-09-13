const protocol = @import("bedrock_protocol");

pub const DecodeLimits = struct {
    protocol: protocol.DecodeLimits = .{},
    max_jwt_header_bytes: usize = 8192,
    max_jwt_payload_bytes: usize = 1024 * 1024,
    max_chain_length: usize = 8,
    max_resource_pack_bytes: u64 = 512 * 1024 * 1024,
    max_resource_packs: usize = 128,

    pub fn validate(self: DecodeLimits) !void {
        const valid =
            self.protocol.valid() and
            self.max_jwt_header_bytes > 0 and
            self.max_jwt_payload_bytes > 0 and
            self.max_chain_length > 0 and
            self.max_resource_pack_bytes > 0 and
            self.max_resource_packs > 0;
        if (!valid) return error.InvalidLimits;
    }
};
