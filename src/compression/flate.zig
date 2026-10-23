const std = @import("std");

const Limits = @import("../limits.zig").Limits;

pub const history_len = std.compress.flate.max_window_len;

pub const minimum_output_bytes = 64;

const native = @import("compression_options").libdeflate;
const Handle = if (native) ?*anyopaque else void;

pub const default_level: u4 = if (native) 3 else 1;

pub const Encoder = struct {
    handle: Handle = if (native) null else {},
    level: u4 = default_level,

    pub fn init(allocator: std.mem.Allocator) !Encoder {
        return initLevel(allocator, default_level);
    }

    pub fn initLevel(allocator: std.mem.Allocator, level: u4) !Encoder {
        if (level < 1 or level > 9) return error.InvalidLimits;
        if (!native) return .{ .level = level };
        const previous = context_allocator;
        context_allocator = allocator;
        defer context_allocator = previous;
        return .{ .handle = libdeflate_alloc_compressor_ex(level, &native_options) orelse return error.OutOfMemory, .level = level };
    }

    pub fn deinit(self: Encoder) void {
        if (native) if (self.handle) |handle| libdeflate_free_compressor(handle);
    }

    pub fn compress(self: Encoder, input: []const u8, output: []u8, history: *[history_len]u8) ![]u8 {
        if (native) if (self.handle) |handle| return compressNative(handle, input, output);
        return compressPure(input, output, history, self.level);
    }
};

pub const Decoder = struct {
    handle: Handle = if (native) null else {},

    pub fn init(allocator: std.mem.Allocator) !Decoder {
        if (!native) return .{};
        const previous = context_allocator;
        context_allocator = allocator;
        defer context_allocator = previous;
        return .{ .handle = libdeflate_alloc_decompressor_ex(&native_options) orelse return error.OutOfMemory };
    }

    pub fn deinit(self: Decoder) void {
        if (native) if (self.handle) |handle| libdeflate_free_decompressor(handle);
    }

    pub fn decompress(self: Decoder, input: []const u8, output: []u8, history: *[history_len]u8, limits: Limits) ![]u8 {
        if (native) if (self.handle) |handle| return decompressNative(handle, input, output, limits);
        return @import("flate.zig").decompress(input, output, history, limits);
    }
};

noinline fn compressNative(handle: *anyopaque, input: []const u8, output: []u8) ![]u8 {
    if (output.len < minimum_output_bytes) return error.NoSpaceLeft;
    const len = libdeflate_deflate_compress(handle, input.ptr, input.len, output.ptr, output.len);
    if (len == 0) return error.NoSpaceLeft;
    return output[0..len];
}

noinline fn decompressNative(handle: *anyopaque, input: []const u8, output: []u8, limits: Limits) ![]u8 {
    if (input.len > limits.max_frame_bytes) return error.LimitExceeded;
    const bounded = output[0..@min(output.len, limits.max_batch_bytes)];
    var consumed: usize = 0;
    var produced: usize = 0;
    switch (libdeflate_deflate_decompress_ex(handle, input.ptr, input.len, bounded.ptr, bounded.len, &consumed, &produced)) {
        0 => {},
        3 => return error.LimitExceeded,
        else => return error.MalformedCompressedData,
    }
    if (consumed != input.len) return error.MalformedCompressedData;
    return bounded[0..produced];
}

const NativeOptions = extern struct {
    sizeof_options: usize = @sizeOf(NativeOptions),
    malloc_func: *const fn (usize) callconv(.c) ?*anyopaque = allocateContext,
    free_func: *const fn (?*anyopaque) callconv(.c) void = freeContext,
};
const native_options: NativeOptions = .{};
const Allocation = struct { allocator: std.mem.Allocator, len: usize };
const allocation_header = std.mem.alignForward(usize, @sizeOf(Allocation), 16);

// libdeflate callbacks have no user data, so each allocation remembers its owner for later destruction.
threadlocal var context_allocator: ?std.mem.Allocator = null;

fn allocateContext(len: usize) callconv(.c) ?*anyopaque {
    const allocator = context_allocator orelse return null;
    const total = std.math.add(usize, allocation_header, len) catch return null;
    const memory = allocator.rawAlloc(total, .@"16", @returnAddress()) orelse return null;
    const header: *Allocation = @ptrCast(@alignCast(memory));
    header.* = .{ .allocator = allocator, .len = total };
    return memory + allocation_header;
}

fn freeContext(pointer: ?*anyopaque) callconv(.c) void {
    const memory: [*]u8 = @ptrCast(pointer orelse return);
    const base = memory - allocation_header;
    const header: Allocation = @as(*Allocation, @ptrCast(@alignCast(base))).*;
    header.allocator.rawFree(base[0..header.len], .@"16", @returnAddress());
}

extern "c" fn libdeflate_alloc_compressor_ex(c_int, *const NativeOptions) ?*anyopaque;
extern "c" fn libdeflate_alloc_decompressor_ex(*const NativeOptions) ?*anyopaque;
extern "c" fn libdeflate_free_compressor(*anyopaque) void;
extern "c" fn libdeflate_free_decompressor(*anyopaque) void;
extern "c" fn libdeflate_deflate_compress(*anyopaque, [*]const u8, usize, [*]u8, usize) usize;
extern "c" fn libdeflate_deflate_decompress_ex(*anyopaque, [*]const u8, usize, [*]u8, usize, *usize, *usize) c_int;

pub fn compress(input: []const u8, output: []u8, history: *[history_len]u8) ![]u8 {
    return compressPure(input, output, history, default_level);
}

pub const fixed_limit = 512;

fn compressPure(input: []const u8, output: []u8, history: *[history_len]u8, level: u4) ![]u8 {
    if (level == 1 and input.len <= fixed_limit) {
        if (compressFixed(input, output)) |bytes| return bytes else |err| if (output.len <= input.len) return err;
    }
    return compressLevel(input, output, history, level);
}

const fixed_table_bits = 10;

/// Inputs must fit the 32 KiB window.
pub fn compressFixed(input: []const u8, output: []u8) ![]u8 {
    std.debug.assert(input.len <= 1 << 15);
    var bits: Bits = .{ .bytes = output };
    try bits.put(0b011, 3);

    var table_bits: u5 = 6;
    while (table_bits < fixed_table_bits and @as(usize, 1) << table_bits < input.len) table_bits += 1;
    const shift: u5 = @intCast(32 - @as(u6, table_bits));
    var table: [1 << fixed_table_bits]u16 = undefined;
    @memset(table[0 .. @as(usize, 1) << table_bits], std.math.maxInt(u16));

    var cursor: usize = 0;
    while (input.len - cursor >= 4) {
        const word = std.mem.readInt(u32, input[cursor..][0..4], .little);
        const slot = (word *% 0x1e35a7bd) >> shift;
        const previous: usize = table[slot];
        table[slot] = @intCast(cursor);
        if (previous >= cursor or std.mem.readInt(u32, input[previous..][0..4], .little) != word) {
            try bits.literal(input[cursor]);
            cursor += 1;
            continue;
        }
        var len: usize = 4;
        const longest = @min(258, input.len - cursor);
        while (len < longest and input[previous + len] == input[cursor + len]) len += 1;
        try bits.match(len, cursor - previous);
        cursor += len;
    }
    for (input[cursor..]) |byte| try bits.literal(byte);
    try bits.code(256);
    return output[0..try bits.finish()];
}

const Bits = struct {
    bytes: []u8,
    len: usize = 0,
    buffer: u64 = 0,
    count: u6 = 0,

    fn put(self: *Bits, value: u64, n: u6) !void {
        self.buffer |= value << self.count;
        self.count += n;
        while (self.count >= 8) {
            if (self.len == self.bytes.len) return error.NoSpaceLeft;
            self.bytes[self.len] = @truncate(self.buffer);
            self.len += 1;
            self.buffer >>= 8;
            self.count -= 8;
        }
    }

    fn code(self: *Bits, symbol: u16) !void {
        const entry = fixed_codes[symbol];
        try self.put(entry.code, entry.len);
    }

    fn literal(self: *Bits, byte: u8) !void {
        try self.code(byte);
    }

    fn match(self: *Bits, len: usize, distance: usize) !void {
        if (len == 258) {
            try self.code(285);
        } else {
            const l = len - 3;
            if (l < 8) {
                try self.code(@intCast(257 + l));
            } else {
                const n: u6 = std.math.log2_int(usize, l);
                try self.code(@intCast(257 + 4 * (@as(usize, n) - 1) + ((l >> (n - 2)) & 3)));
                try self.put(l & ((@as(usize, 1) << (n - 2)) - 1), n - 2);
            }
        }
        const d = distance - 1;
        if (d < 4) {
            try self.put(@bitReverse(@as(u5, @intCast(d))), 5);
        } else {
            const n: u6 = std.math.log2_int(usize, d);
            try self.put(@bitReverse(@as(u5, @intCast(2 * @as(usize, n) + ((d >> (n - 1)) & 1)))), 5);
            try self.put(d & ((@as(usize, 1) << (n - 1)) - 1), n - 1);
        }
    }

    fn finish(self: *Bits) !usize {
        if (self.count != 0) {
            if (self.len == self.bytes.len) return error.NoSpaceLeft;
            self.bytes[self.len] = @truncate(self.buffer);
            self.len += 1;
        }
        return self.len;
    }
};

const Code = struct { code: u16, len: u6 };

// RFC 1951 3.2.6, with each code reversed since DEFLATE writes Huffman codes from their top bit.
const fixed_codes = blk: {
    var codes: [288]Code = undefined;
    for (&codes, 0..) |*entry, symbol| {
        const value: u16, const len: u6 = if (symbol < 144)
            .{ 0x30 + symbol, 8 }
        else if (symbol < 256)
            .{ 0x190 + symbol - 144, 9 }
        else if (symbol < 280)
            .{ symbol - 256, 7 }
        else
            .{ 0xc0 + symbol - 280, 8 };
        entry.* = .{ .code = @bitReverse(value) >> @intCast(16 - len), .len = len };
    }
    break :blk codes;
};

/// Keep std's large compressor stack frame out of callers.
noinline fn compressLevel(input: []const u8, output: []u8, history: *[history_len]u8, level: u4) ![]u8 {
    // std's compressor asserts when given less than 64 bytes.
    if (output.len < minimum_output_bytes) return error.NoSpaceLeft;

    const options: std.compress.flate.Compress.Options = switch (level) {
        1 => .level_1,
        2 => .level_2,
        3 => .level_3,
        4 => .level_4,
        5 => .level_5,
        7 => .level_7,
        8 => .level_8,
        9 => .level_9,
        else => .level_6,
    };
    var writer: std.Io.Writer = .fixed(output);
    var compressor: std.compress.flate.Compress = try .init(&writer, history, .raw, options);

    compressor.writer.writeAll(input) catch return error.NoSpaceLeft;
    compressor.finish() catch return error.NoSpaceLeft;

    return output[0..writer.end];
}

pub fn decompress(input: []const u8, output: []u8, history: *[history_len]u8, limits: Limits) ![]u8 {
    if (input.len > limits.max_frame_bytes) return error.LimitExceeded;

    const bounded = output[0..@min(output.len, limits.max_batch_bytes)];
    var reader: std.Io.Reader = .fixed(input);
    var decompressor: std.compress.flate.Decompress = .init(&reader, .raw, history);
    var writer: std.Io.Writer = .fixed(bounded);

    const len = decompressor.reader.streamRemaining(&writer) catch {
        if (decompressor.err != null) return error.MalformedCompressedData;
        return error.LimitExceeded;
    };
    if (reader.seek != reader.end) return error.MalformedCompressedData;

    return bounded[0..len];
}

test "fixed blocks inflate back to the input across sizes and match shapes" {
    var prng = std.Random.DefaultPrng.init(0xf1ed);
    const random = prng.random();
    var input: [1 << 15]u8 = undefined;
    var output: [(1 << 15) + (1 << 13)]u8 = undefined;
    var restored: [1 << 15]u8 = undefined;
    var history: [history_len]u8 = undefined;

    for ([_]usize{ 0, 1, 3, 4, 5, 64, 300, 1000, 4096, 1 << 15 }) |len| for (0..4) |shape| {
        for (input[0..len], 0..) |*byte, i| byte.* = switch (shape) {
            0 => random.int(u8),
            1 => 'z',
            2 => @truncate(i / 7),
            else => if (random.uintLessThan(u8, 4) == 0) random.int(u8) else @truncate(i % 300),
        };
        const packed_bytes = try compressFixed(input[0..len], &output);
        const unpacked = try decompress(packed_bytes, &restored, &history, .{});
        try std.testing.expectEqualSlices(u8, input[0..len], unpacked);
    };
}

test "level 1 sends small batches through fixed blocks and falls back to std when they grow" {
    var history: [history_len]u8 = undefined;
    var restored: [600]u8 = undefined;
    var input: [fixed_limit + 1]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(9);
    prng.random().bytes(&input);
    var output: [700]u8 = undefined;

    const tiny = try compress("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", &output, &history);
    try std.testing.expect(tiny.len < 10);
    try std.testing.expectEqualSlices(u8, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", try decompress(tiny, &restored, &history, .{}));

    const noise = try compress(input[0..fixed_limit], &output, &history);
    try std.testing.expectEqualSlices(u8, input[0..fixed_limit], try decompress(noise, &restored, &history, .{}));
    try std.testing.expectError(error.NoSpaceLeft, compress(input[0..fixed_limit], output[0 .. fixed_limit - 1], &history));
}

test "fixed blocks report a full output instead of truncating" {
    var input: [512]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(3);
    prng.random().bytes(&input);
    var output: [511]u8 = undefined;
    try std.testing.expectError(error.NoSpaceLeft, compressFixed(&input, &output));
}
