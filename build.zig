const std = @import("std");

pub fn build(b: *std.Build) void {
    const version = @import("builtin").zig_version;
    if (comptime version.major != 0 or version.minor != 16 or version.patch != 0) {
        @compileError("zigrock requires Zig 0.16.0");
    }
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const protocol = b.dependency("bedrock_protocol", .{ .target = target, .optimize = optimize });
    const zigrock = b.addModule("zigrock", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "bedrock_protocol", .module = protocol.module("bedrock_protocol") }},
    });
    b.installArtifact(b.addLibrary(.{ .name = "zigrock", .root_module = zigrock }));
    const tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("tests/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zigrock", .module = zigrock },
        },
    }) });
    b.step("test", "Run zigrock tests").dependOn(&b.addRunArtifact(tests).step);
}
