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
    if (level != 1) return compressLevel(input, output, history, level);
    if (input.len <= fixed_limit) {
        if (compressFixed(input, output)) |bytes| return bytes else |err| if (output.len <= input.len) return err;
    }
    return compressFast(input, output, history);
}

const fixed_table_bits = 10;

/// Inputs must fit the 32 KiB window.
pub fn compressFixed(input: []const u8, output: []u8) ![]u8 {
    std.debug.assert(input.len <= 1 << 15);
    var bits: Bits = .{ .bytes = output };
    bits.put(0b011, 3);

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
            bits.symbol(&fixed_literals, input[cursor]);
            cursor += 1;
            continue;
        }
        const len = matchLength(input, previous, cursor);
        bits.match(&fixed_literals, &fixed_distances, len, cursor - previous);
        cursor += len;
    }
    for (input[cursor..]) |byte| bits.symbol(&fixed_literals, byte);
    bits.symbol(&fixed_literals, 256);
    return output[0..try bits.finish()];
}

const fast_table_bits = 14;
const fast_table_bytes = 2 << fast_table_bits;
const fast_tokens = (history_len - fast_table_bytes) / 4;
const fast_stride = 32;

/// Level 1 past the fixed block limit: one hash probe per position, then each block goes out stored, with the
/// fixed codes or with its own, whichever is smallest. `history` holds the hash table and the block's tokens.
noinline fn compressFast(input: []const u8, output: []u8, history: *[history_len]u8) ![]u8 {
    const table: *align(1) [1 << fast_table_bits]u16 = @ptrCast(history[0..fast_table_bytes]);
    const tokens: *align(1) [fast_tokens]u32 = @ptrCast(history[fast_table_bytes..][0 .. fast_tokens * 4]);

    var table_bits: u5 = 9;
    while (table_bits < fast_table_bits and @as(usize, 1) << table_bits < input.len) table_bits += 1;
    const shift: u5 = @intCast(32 - @as(u6, table_bits));
    @memset(table[0 .. @as(usize, 1) << table_bits], 0);

    var bits: Bits = .{ .bytes = output };
    var block: Block = .{};
    var start: usize = 0;
    var cursor: usize = 0;
    var misses: usize = 0;
    while (input.len - cursor >= 4) {
        // Room for a full stride and the last three bytes of the input
        if (block.count + fast_stride + 3 > fast_tokens) {
            block.write(&bits, tokens, input[start..cursor], false);
            block = .{};
            start = cursor;
        }
        const word = std.mem.readInt(u32, input[cursor..][0..4], .little);
        const slot = (word *% 0x1e35a7bd) >> shift;
        // Positions are kept modulo 64 KiB, and the compare below settles whether a slot really points at this word
        const distance: usize = @as(u16, @truncate(cursor)) -% table[slot];
        table[slot] = @truncate(cursor);
        if (distance != 0 and distance <= 1 << 15 and distance <= cursor and
            std.mem.readInt(u32, input[cursor - distance ..][0..4], .little) == word)
        {
            const len = matchLength(input, cursor - distance, cursor);
            block.match(tokens, len, distance);
            cursor += len;
            misses = 0;
            continue;
        }
        const step = @min(1 + (misses >> 5), fast_stride, input.len - cursor);
        for (input[cursor..][0..step]) |byte| block.literal(tokens, byte);
        cursor += step;
        misses += 1;
    }
    for (input[cursor..]) |byte| block.literal(tokens, byte);
    block.write(&bits, tokens, input[start..], true);
    return output[0..try bits.finish()];
}

/// `a` and `b` already agree on four bytes.
fn matchLength(input: []const u8, a: usize, b: usize) usize {
    const limit = @min(258, input.len - b);
    var len: usize = 4;
    while (len + 8 <= limit) : (len += 8) {
        const differing = std.mem.readInt(u64, input[a + len ..][0..8], .little) ^ std.mem.readInt(u64, input[b + len ..][0..8], .little);
        if (differing != 0) return len + (@ctz(differing) >> 3);
    }
    while (len < limit and input[a + len] == input[b + len]) len += 1;
    return len;
}

const Code = struct { code: u16, len: u8 };
const literal_symbols = 286;
const distance_symbols = 30;
const end_of_block = 256;

const length_symbols: [256]u16 = blk: {
    @setEvalBranchQuota(10_000);
    var table: [256]u16 = undefined;
    for (&table, 0..) |*symbol, l| {
        if (l < 8) {
            symbol.* = 257 + l;
        } else {
            const n: usize = std.math.log2_int(usize, l);
            symbol.* = 257 + 4 * (n - 1) + ((l >> @intCast(n - 2)) & 3);
        }
    }
    table[255] = 285;
    break :blk table;
};

const distance_symbols_by_value: [512]u8 = blk: {
    @setEvalBranchQuota(10_000);
    var table: [512]u8 = undefined;
    for (table[0..256], 0..) |*symbol, d| symbol.* = distanceSymbolOf(d);
    for (table[256..], 0..) |*symbol, top| symbol.* = distanceSymbolOf(top << 7);
    break :blk table;
};

fn distanceSymbolOf(d: usize) u8 {
    if (d < 4) return @intCast(d);
    const n: usize = std.math.log2_int(usize, d);
    return @intCast(2 * n + ((d >> @intCast(n - 1)) & 1));
}

inline fn lengthSymbol(len: usize) u16 {
    return length_symbols[len - 3];
}

inline fn lengthExtra(symbol: u16) u6 {
    return if (symbol < 265 or symbol == 285) 0 else @intCast((symbol - 261) / 4);
}

inline fn distanceSymbol(distance: usize) u16 {
    const d = distance - 1;
    return distance_symbols_by_value[if (d < 256) d else 256 + (d >> 7)];
}

inline fn distanceExtra(symbol: u16) u6 {
    return if (symbol < 4) 0 else @intCast(symbol / 2 - 1);
}

const Block = struct {
    literals: [literal_symbols]u16 = @splat(0),
    distances: [distance_symbols]u16 = @splat(0),
    count: usize = 0,
    extra_bits: usize = 0,

    const match_flag = 1 << 31;

    inline fn literal(self: *Block, tokens: *align(1) [fast_tokens]u32, byte: u8) void {
        tokens[self.count] = byte;
        self.count += 1;
        self.literals[byte] += 1;
    }

    inline fn match(self: *Block, tokens: *align(1) [fast_tokens]u32, len: usize, distance: usize) void {
        tokens[self.count] = @intCast(match_flag | (len - 3) << 16 | (distance - 1));
        self.count += 1;
        const length = lengthSymbol(len);
        const reach = distanceSymbol(distance);
        self.literals[length] += 1;
        self.distances[reach] += 1;
        self.extra_bits += @as(usize, lengthExtra(length)) + distanceExtra(reach);
    }

    fn write(self: *Block, bits: *Bits, tokens: *align(1) const [fast_tokens]u32, raw: []const u8, final: bool) void {
        self.literals[end_of_block] = 1;

        var literal_lens: [literal_symbols]u8 = undefined;
        var distance_lens: [distance_symbols]u8 = undefined;
        codeLengths(literal_symbols, 15, &self.literals, &literal_lens);
        codeLengths(distance_symbols, 15, &self.distances, &distance_lens);
        const header: Header = .init(&literal_lens, &distance_lens);

        var dynamic_bits: usize = 3 + header.bits + self.extra_bits;
        var fixed_bits: usize = 3 + self.extra_bits;
        for (self.literals, literal_lens, fixed_literals) |uses, len, fixed| {
            dynamic_bits += @as(usize, uses) * len;
            fixed_bits += @as(usize, uses) * fixed.len;
        }
        for (self.distances, distance_lens) |uses, len| {
            dynamic_bits += @as(usize, uses) * len;
            fixed_bits += @as(usize, uses) * 5;
        }
        const stored_bits = if (raw.len <= std.math.maxInt(u16)) 3 + 7 + 32 + 8 * raw.len else std.math.maxInt(usize);

        bits.put(@intFromBool(final), 1);
        if (stored_bits <= @min(dynamic_bits, fixed_bits)) {
            bits.put(0b00, 2);
            bits.stored(raw);
            return;
        }
        if (fixed_bits <= dynamic_bits) {
            bits.put(0b01, 2);
            self.emit(bits, tokens, &fixed_literals, &fixed_distances);
            return;
        }
        bits.put(0b10, 2);
        header.write(bits);
        var literal_codes: [literal_symbols]Code = undefined;
        var distance_codes: [distance_symbols]Code = undefined;
        canonical(&literal_lens, &literal_codes);
        canonical(&distance_lens, &distance_codes);
        self.emit(bits, tokens, &literal_codes, &distance_codes);
    }

    fn emit(self: *const Block, bits: *Bits, tokens: *align(1) const [fast_tokens]u32, literals: *const [literal_symbols]Code, distances: *const [distance_symbols]Code) void {
        for (tokens[0..self.count]) |token| {
            if (token & match_flag == 0) {
                bits.symbol(literals, @intCast(token));
            } else {
                bits.match(literals, distances, ((token >> 16) & 0xff) + 3, (token & 0x7fff) + 1);
            }
        }
        bits.symbol(literals, end_of_block);
    }
};

const Header = struct {
    runs: [literal_symbols + distance_symbols]Run = undefined,
    run_count: usize = 0,
    literal_count: usize,
    distance_count: usize,
    lens: [19]u8 = undefined,
    sent: usize = 19,
    bits: usize = 0,

    const Run = struct { symbol: u8, extra: u8 };
    const order = [19]u8{ 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };
    const extra_bits = [19]u6{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 7 };

    fn init(literal_lens: *const [literal_symbols]u8, distance_lens: *const [distance_symbols]u8) Header {
        var literal_count: usize = literal_symbols;
        while (literal_lens[literal_count - 1] == 0) literal_count -= 1;
        var distance_count: usize = distance_symbols;
        while (distance_count > 1 and distance_lens[distance_count - 1] == 0) distance_count -= 1;
        var self: Header = .{ .literal_count = literal_count, .distance_count = distance_count };

        var all: [literal_symbols + distance_symbols]u8 = undefined;
        @memcpy(all[0..literal_count], literal_lens[0..literal_count]);
        @memcpy(all[literal_count..][0..distance_count], distance_lens[0..distance_count]);
        const total = literal_count + distance_count;

        var uses: [19]u16 = @splat(0);
        var i: usize = 0;
        while (i < total) {
            const len = all[i];
            var run: usize = 1;
            while (i + run < total and all[i + run] == len) run += 1;
            i += run;
            if (len == 0) {
                while (run >= 11) {
                    const taken = @min(run, 138);
                    self.add(&uses, 18, taken - 11);
                    run -= taken;
                }
                if (run >= 3) {
                    self.add(&uses, 17, run - 3);
                    run = 0;
                }
            } else {
                self.add(&uses, len, 0);
                run -= 1;
                while (run >= 3) {
                    const taken = @min(run, 6);
                    self.add(&uses, 16, taken - 3);
                    run -= taken;
                }
            }
            for (0..run) |_| self.add(&uses, len, 0);
        }

        codeLengths(19, 7, &uses, &self.lens);
        while (self.sent > 4 and self.lens[order[self.sent - 1]] == 0) self.sent -= 1;
        self.bits = 5 + 5 + 4 + 3 * self.sent;
        for (uses, self.lens, extra_bits) |count, len, extra| self.bits += @as(usize, count) * (len + extra);
        return self;
    }

    fn add(self: *Header, uses: *[19]u16, symbol: u8, extra: usize) void {
        self.runs[self.run_count] = .{ .symbol = symbol, .extra = @intCast(extra) };
        self.run_count += 1;
        uses[symbol] += 1;
    }

    fn write(self: *const Header, bits: *Bits) void {
        bits.put(self.literal_count - 257, 5);
        bits.put(self.distance_count - 1, 5);
        bits.put(self.sent - 4, 4);
        for (order[0..self.sent]) |symbol| bits.put(self.lens[symbol], 3);
        var codes: [19]Code = undefined;
        canonical(&self.lens, &codes);
        for (self.runs[0..self.run_count]) |run| {
            const entry = codes[run.symbol];
            bits.put(entry.code | @as(u64, run.extra) << @intCast(entry.len), @intCast(entry.len + extra_bits[run.symbol]));
        }
    }
};

/// Length-limited Huffman code lengths, the way miniz builds them: Moffat and Katajainen's in-place minimum
/// redundancy over the sorted counts, then the longest codes are shortened until the limit holds.
fn codeLengths(comptime symbols: usize, comptime limit: u5, uses: *const [symbols]u16, lens: *[symbols]u8) void {
    @memset(lens, 0);
    var sorted: [symbols]u32 = undefined;
    var n: usize = 0;
    for (uses, 0..) |count, symbol| if (count != 0) {
        sorted[n] = @as(u32, count) << 16 | @as(u32, @intCast(symbol));
        n += 1;
    };
    // Decoders want at least two codes, so a lone symbol gets a neighbour that is never sent
    if (n < 2) {
        const only: usize = if (n == 1) sorted[0] & 0xffff else 0;
        lens[only] = 1;
        lens[if (only == 0) 1 else 0] = 1;
        return;
    }
    sortByCount(symbols, &sorted, n);

    var keys: [symbols]u16 = undefined;
    for (sorted[0..n], keys[0..n]) |entry, *key| key.* = @intCast(entry >> 16);
    keys[0] += keys[1];
    var root: usize = 0;
    var leaf: usize = 2;
    var next: usize = 1;
    while (next < n - 1) : (next += 1) {
        if (leaf >= n or keys[root] < keys[leaf]) {
            keys[next] = keys[root];
            keys[root] = @intCast(next);
            root += 1;
        } else {
            keys[next] = keys[leaf];
            leaf += 1;
        }
        if (leaf >= n or (root < next and keys[root] < keys[leaf])) {
            keys[next] += keys[root];
            keys[root] = @intCast(next);
            root += 1;
        } else {
            keys[next] += keys[leaf];
            leaf += 1;
        }
    }
    keys[n - 2] = 0;
    var back = n - 2;
    while (back > 0) {
        back -= 1;
        keys[back] = keys[keys[back]] + 1;
    }
    var available: usize = 1;
    var used: usize = 0;
    var depth: u16 = 0;
    var internal: usize = n - 1;
    next = n;
    while (available > 0) {
        while (internal > 0 and keys[internal - 1] == depth) {
            used += 1;
            internal -= 1;
        }
        while (available > used) {
            next -= 1;
            keys[next] = depth;
            available -= 1;
        }
        available = 2 * used;
        depth += 1;
        used = 0;
    }

    var counts: [33]u16 = @splat(0);
    for (keys[0..n]) |len| counts[@min(len, 32)] += 1;
    for (limit + 1..33) |len| counts[limit] += counts[len];
    var total: u32 = 0;
    for (1..@as(usize, limit) + 1) |len| total += @as(u32, counts[len]) << @intCast(limit - len);
    while (total != @as(u32, 1) << limit) : (total -= 1) {
        counts[limit] -= 1;
        var len: usize = limit - 1;
        while (counts[len] == 0) len -= 1;
        counts[len] -= 1;
        counts[len + 1] += 2;
    }

    var position = n;
    for (1..@as(usize, limit) + 1) |len| for (0..counts[len]) |_| {
        position -= 1;
        lens[sorted[position] & 0xffff] = @intCast(len);
    };
}

fn sortByCount(comptime symbols: usize, sorted: *[symbols]u32, n: usize) void {
    var other: [symbols]u32 = undefined;
    var from: []u32 = sorted[0..n];
    var to: []u32 = other[0..n];
    var wide: u32 = 0;
    for (from) |entry| wide |= entry;
    const passes: usize = if (wide >> 24 == 0) 1 else 2;
    for (0..passes) |pass| {
        const shift: u5 = @intCast(16 + 8 * pass);
        var offsets: [257]u16 = @splat(0);
        for (from) |entry| offsets[((entry >> shift) & 0xff) + 1] += 1;
        for (offsets[1..], offsets[0..256]) |*offset, before| offset.* += before;
        for (from) |entry| {
            const bucket = (entry >> shift) & 0xff;
            to[offsets[bucket]] = entry;
            offsets[bucket] += 1;
        }
        std.mem.swap([]u32, &from, &to);
    }
    if (passes == 1) @memcpy(sorted[0..n], other[0..n]);
}

/// Codes come out reversed, since DEFLATE sends a Huffman code from its top bit.
fn canonical(lens: []const u8, codes: []Code) void {
    var counts: [16]u16 = @splat(0);
    for (lens) |len| counts[len] += 1;
    counts[0] = 0;
    var next: [16]u16 = undefined;
    var code: u16 = 0;
    for (1..16) |len| {
        code = (code + counts[len - 1]) << 1;
        next[len] = code;
    }
    for (lens, codes) |len, *entry| {
        if (len == 0) {
            entry.* = .{ .code = 0, .len = 0 };
            continue;
        }
        entry.* = .{ .code = @bitReverse(next[len]) >> @intCast(16 - @as(u8, len)), .len = len };
        next[len] += 1;
    }
}

const fixed_literals: [literal_symbols]Code = blk: {
    var lens: [288]u8 = undefined;
    for (&lens, 0..) |*len, symbol| len.* = if (symbol < 144) 8 else if (symbol < 256) 9 else if (symbol < 280) 7 else 8;
    var codes: [288]Code = undefined;
    canonical(&lens, &codes);
    break :blk codes[0..literal_symbols].*;
};

const fixed_distances: [distance_symbols]Code = blk: {
    const lens: [32]u8 = @splat(5);
    var codes: [32]Code = undefined;
    canonical(&lens, &codes);
    break :blk codes[0..distance_symbols].*;
};

/// Runs past the end of the output rather than failing each write, and `finish` reports it.
const Bits = struct {
    bytes: []u8,
    len: usize = 0,
    buffer: u64 = 0,
    count: u6 = 0,
    full: bool = false,

    /// At most 32 bits a call.
    inline fn put(self: *Bits, value: u64, n: u6) void {
        self.buffer |= value << self.count;
        self.count += n;
        if (self.count >= 32) self.flush();
    }

    fn flush(self: *Bits) void {
        if (self.bytes.len - self.len >= 4) {
            std.mem.writeInt(u32, self.bytes[self.len..][0..4], @truncate(self.buffer), .little);
            self.len += 4;
        } else {
            self.full = true;
        }
        self.buffer >>= 32;
        self.count -= 32;
    }

    inline fn symbol(self: *Bits, codes: *const [literal_symbols]Code, value: u16) void {
        const entry = codes[value];
        self.put(entry.code, @intCast(entry.len));
    }

    inline fn match(self: *Bits, literals: *const [literal_symbols]Code, distances: *const [distance_symbols]Code, len: usize, distance: usize) void {
        const length = lengthSymbol(len);
        const length_code = literals[length];
        const length_extra = lengthExtra(length);
        const l = len - 3;
        self.put(length_code.code | (l & ((@as(u64, 1) << length_extra) - 1)) << @intCast(length_code.len), @intCast(length_code.len + length_extra));

        const reach = distanceSymbol(distance);
        const reach_code = distances[reach];
        const reach_extra = distanceExtra(reach);
        const d = distance - 1;
        self.put(reach_code.code | (d & ((@as(u64, 1) << reach_extra) - 1)) << @intCast(reach_code.len), @intCast(reach_code.len + reach_extra));
    }

    fn stored(self: *Bits, raw: []const u8) void {
        self.count = @intCast(std.mem.alignForward(usize, self.count, 8));
        const pending = @as(usize, self.count) / 8;
        if (self.bytes.len - self.len < pending + 4 + raw.len) {
            self.full = true;
            return;
        }
        for (self.bytes[self.len..][0..pending]) |*byte| {
            byte.* = @truncate(self.buffer);
            self.buffer >>= 8;
        }
        self.len += pending;
        self.count = 0;
        std.mem.writeInt(u16, self.bytes[self.len..][0..2], @intCast(raw.len), .little);
        std.mem.writeInt(u16, self.bytes[self.len + 2 ..][0..2], ~@as(u16, @intCast(raw.len)), .little);
        @memcpy(self.bytes[self.len + 4 ..][0..raw.len], raw);
        self.len += 4 + raw.len;
    }

    fn finish(self: *Bits) !usize {
        const pending = (@as(usize, self.count) + 7) / 8;
        if (self.full or self.bytes.len - self.len < pending) return error.NoSpaceLeft;
        for (self.bytes[self.len..][0..pending]) |*byte| {
            byte.* = @truncate(self.buffer);
            self.buffer >>= 8;
        }
        return self.len + pending;
    }
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

test "level 1 round-trips stored, fixed and dynamic blocks across sizes and shapes" {
    const gpa = std.testing.allocator;
    const max = 300_000;
    const input = try gpa.alloc(u8, max);
    defer gpa.free(input);
    const output = try gpa.alloc(u8, max + max / 64 + 64);
    defer gpa.free(output);
    const restored = try gpa.alloc(u8, max);
    defer gpa.free(restored);
    const histories = try gpa.alloc([history_len]u8, 2);
    defer gpa.free(histories);
    const decoder: Decoder = try .init(gpa);
    defer decoder.deinit();
    const encoder: Encoder = .{ .level = 1 };
    var prng = std.Random.DefaultPrng.init(0xdef1a7e);
    const random = prng.random();
    const words = [_][]const u8{ "minecraft:", "stone", "player", "position", "\x00\x00\x80\x3f", "runtime_id", "chunk", "air" };

    for ([_]usize{ fixed_limit + 1, 600, 4096, 20_000, 70_000, 140_000, max }) |len| for (0..6) |shape| {
        switch (shape) {
            0 => random.bytes(input[0..len]),
            1 => @memset(input[0..len], 'z'),
            2 => for (input[0..len], 0..) |*byte, i| {
                byte.* = @truncate(i / 7);
            },
            3 => for (input[0..len], 0..) |*byte, i| {
                byte.* = if (random.uintLessThan(u8, 4) == 0) random.int(u8) else @truncate(i % 300);
            },
            4 => {
                var at: usize = 0;
                while (at < len) {
                    const word = words[random.uintLessThan(usize, words.len)];
                    const taken = @min(word.len, len - at);
                    @memcpy(input[at..][0..taken], word[0..taken]);
                    at += taken;
                }
            },
            else => {
                const period = @min(len, 30_000);
                random.bytes(input[0..period]);
                for (input[period..len], 0..) |*byte, i| byte.* = input[i];
            },
        }
        random.bytes(&histories[0]);
        const packed_bytes = try encoder.compress(input[0..len], output, &histories[0]);
        try std.testing.expect(packed_bytes.len < len + len / 1000 + 64);
        if (shape == 1 or shape == 4) try std.testing.expect(packed_bytes.len < len / 3);
        const unpacked = try decoder.decompress(packed_bytes, restored, &histories[1], .{});
        try std.testing.expectEqualSlices(u8, input[0..len], unpacked);

        const copy = try gpa.dupe(u8, packed_bytes);
        defer gpa.free(copy);
        @memset(&histories[0], 0xa5);
        try std.testing.expectEqualSlices(u8, copy, try encoder.compress(input[0..len], output, &histories[0]));
    };
}

test "level 1 reports a full output instead of truncating" {
    var history: [history_len]u8 = undefined;
    var input: [4000]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(5);
    prng.random().bytes(&input);
    var output: [4100]u8 = undefined;
    const encoder: Encoder = .{ .level = 1 };
    for ([_]usize{ 0, 1, 3, 1000, 3999, 4003 }) |room| try std.testing.expectError(error.NoSpaceLeft, encoder.compress(&input, output[0..room], &history));
    @memset(input[0..2000], 7);
    for ([_]usize{ 0, 2, 900, 2000 }) |room| try std.testing.expectError(error.NoSpaceLeft, encoder.compress(&input, output[0..room], &history));
    _ = try encoder.compress(&input, &output, &history);
}

test "code lengths stay complete and within the limit however skewed the counts" {
    var uses: [literal_symbols]u16 = @splat(0);
    var lens: [literal_symbols]u8 = undefined;
    var a: u16 = 1;
    var b: u16 = 1;
    for (uses[0..22]) |*count| {
        count.* = a;
        const next = a + b;
        a = b;
        b = next;
    }
    for ([_]usize{ 1, 2, 3, 22, literal_symbols }) |used| {
        for (uses[22..], 22..) |*count, symbol| count.* = if (symbol < used) 1 else 0;
        codeLengths(literal_symbols, 15, &uses, &lens);
        var kraft: u32 = 0;
        for (lens, uses) |len, count| {
            try std.testing.expect(len <= 15);
            try std.testing.expect((len != 0) == (count != 0));
            if (len != 0) kraft += @as(u32, 1) << @intCast(15 - len);
        }
        try std.testing.expectEqual(@as(u32, 1 << 15), kraft);
    }

    var few: [19]u16 = @splat(0);
    var few_lens: [19]u8 = undefined;
    codeLengths(19, 7, &few, &few_lens);
    try std.testing.expectEqualSlices(u8, &.{ 1, 1 }, few_lens[0..2]);
    few[9] = 4;
    codeLengths(19, 7, &few, &few_lens);
    try std.testing.expect(few_lens[9] == 1 and few_lens[0] == 1 and few_lens[1] == 0);
}

test "level 1 stays in bounds when a block of tokens fills up at any point" {
    var input: [fast_tokens + 64]u8 = undefined;
    var output: [fast_tokens + 256]u8 = undefined;
    var restored: [fast_tokens + 64]u8 = undefined;
    var histories: [2][history_len]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(11);
    for (&input, 0..) |*byte, i| byte.* = if (i % 3 == 0) prng.random().int(u8) else @truncate(i);
    const encoder: Encoder = .{ .level = 1 };
    for (fast_tokens - 48..input.len) |len| {
        const packed_bytes = try encoder.compress(input[0..len], &output, &histories[0]);
        try std.testing.expectEqualSlices(u8, input[0..len], try decompress(packed_bytes, &restored, &histories[1], .{}));
    }
}
