const std = @import("std");

const Limits = @import("../limits.zig").Limits;

// bedrock uses raw deflate with no zlib wrapper
pub const history_len = std.compress.flate.max_window_len;

pub const minimum_output_bytes = 64;

/// raw deflate compression using the 32k history window
pub fn compress(input: []const u8, output: []u8, history: *[history_len]u8) ![]u8 {
    // zig stdlib flate panics if output is smaller than 64 bytes instead of returning an error
    if (output.len < minimum_output_bytes) return error.NoSpaceLeft;

    var writer: std.Io.Writer = .fixed(output);
    var compressor: std.compress.flate.Compress = try .init(&writer, history, .raw, .default);

    compressor.writer.writeAll(input) catch return error.NoSpaceLeft;
    compressor.finish() catch return error.NoSpaceLeft;

    return output[0..writer.end];
}

/// raw deflate decompression bounded by limits.max_batch_bytes
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
