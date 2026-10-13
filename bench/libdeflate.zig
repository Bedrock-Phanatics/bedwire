const bedwire = @import("bedwire");

const Compressor = opaque {};
const Decompressor = opaque {};
extern "c" fn bw_alloc_compressor(c_int) ?*Compressor;
extern "c" fn bw_alloc_decompressor() ?*Decompressor;
pub extern "c" fn bw_allocations() usize;
pub extern "c" fn bw_live_bytes() usize;
pub extern "c" fn bw_peak_bytes() usize;
pub extern "c" fn bw_reset_peak() void;
pub extern "c" fn bw_fail_after(usize) void;
pub extern "c" fn bw_compressor_bytes() usize;
pub extern "c" fn bw_decompressor_bytes() usize;
extern "c" fn libdeflate_free_compressor(?*Compressor) void;
extern "c" fn libdeflate_free_decompressor(?*Decompressor) void;
extern "c" fn libdeflate_deflate_compress(*Compressor, [*]const u8, usize, [*]u8, usize) usize;
extern "c" fn libdeflate_deflate_decompress_ex(*Decompressor, [*]const u8, usize, [*]u8, usize, *usize, *usize) c_int;

pub const Context = struct {
    compressor: *Compressor,
    decompressor: *Decompressor,

    pub fn init(level: c_int) !Context {
        const compressor = bw_alloc_compressor(level) orelse return error.OutOfMemory;
        errdefer libdeflate_free_compressor(compressor);
        return .{ .compressor = compressor, .decompressor = bw_alloc_decompressor() orelse return error.OutOfMemory };
    }

    pub fn deinit(self: Context) void {
        libdeflate_free_compressor(self.compressor);
        libdeflate_free_decompressor(self.decompressor);
    }

    pub fn compress(self: Context, input: []const u8, output: []u8) ![]u8 {
        if (output.len < bedwire.compression.flate.minimum_output_bytes) return error.NoSpaceLeft;
        const len = libdeflate_deflate_compress(self.compressor, input.ptr, input.len, output.ptr, output.len);
        if (len == 0) return error.NoSpaceLeft;
        return output[0..len];
    }

    pub fn decompress(self: Context, input: []const u8, output: []u8, limits: bedwire.Limits) ![]u8 {
        if (input.len > limits.max_frame_bytes) return error.LimitExceeded;
        const bounded = output[0..@min(output.len, limits.max_batch_bytes)];
        var consumed: usize = 0;
        var produced: usize = 0;
        switch (libdeflate_deflate_decompress_ex(self.decompressor, input.ptr, input.len, bounded.ptr, bounded.len, &consumed, &produced)) {
            0 => {},
            3 => return error.LimitExceeded,
            else => return error.MalformedCompressedData,
        }
        if (consumed != input.len) return error.MalformedCompressedData;
        return bounded[0..produced];
    }
};
