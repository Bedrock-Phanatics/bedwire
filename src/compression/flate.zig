const std = @import("std");

const Limits = @import("../limits.zig").Limits;

pub const history_len = std.compress.flate.max_window_len;

pub const minimum_output_bytes = 64;

const native = @import("compression_options").libdeflate;
const Handle = if (native) ?*anyopaque else void;

pub const Encoder = struct {
    handle: Handle = if (native) null else {},

    pub fn init(allocator: std.mem.Allocator) !Encoder {
        if (!native) return .{};
        const previous = context_allocator;
        context_allocator = allocator;
        defer context_allocator = previous;
        return .{ .handle = libdeflate_alloc_compressor_ex(3, &native_options) orelse return error.OutOfMemory };
    }

    pub fn deinit(self: Encoder) void {
        if (native) if (self.handle) |handle| libdeflate_free_compressor(handle);
    }

    pub fn compress(self: Encoder, input: []const u8, output: []u8, history: *[history_len]u8) ![]u8 {
        if (native) if (self.handle) |handle| return compressNative(handle, input, output);
        return @import("flate.zig").compress(input, output, history);
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

// libdeflate callbacks have no user data; each allocation remembers its owner for later destruction.
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

/// Keep std's large compressor stack frame out of callers.
pub noinline fn compress(input: []const u8, output: []u8, history: *[history_len]u8) ![]u8 {
    // std's compressor asserts when given less than 64 bytes.
    if (output.len < minimum_output_bytes) return error.NoSpaceLeft;

    var writer: std.Io.Writer = .fixed(output);
    var compressor: std.compress.flate.Compress = try .init(&writer, history, .raw, .default);

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
