const std = @import("std");

const Limits = @import("../limits.zig").Limits;

pub const history_len = std.compress.flate.max_window_len;

pub const minimum_output_bytes = 64;

/// Raw DEFLATE. Kept out of line: std's compressor is a ~230 KiB stack local
/// that would otherwise inflate every caller's frame.
pub noinline fn compress(input: []const u8, output: []u8, history: *[history_len]u8) ![]u8 {
    // std's compressor asserts instead of erroring below 64 bytes.
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
