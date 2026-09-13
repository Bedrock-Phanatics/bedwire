const std = @import("std");

pub fn build(b: *std.Build) void {
    const version = @import("builtin").zig_version;
    if (comptime version.major != 0 or version.minor != 16 or version.patch != 0) {
        @compileError("bedwire requires Zig 0.16.0");
    }
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const protocol = b.dependency("bedrock_protocol", .{ .target = target, .optimize = optimize });
    const bedwire = b.addModule("bedwire", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "bedrock_protocol", .module = protocol.module("bedrock_protocol") }},
    });
    b.installArtifact(b.addLibrary(.{ .name = "bedwire", .root_module = bedwire }));
    const tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("tests/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "bedwire", .module = bedwire },
        },
    }) });
    b.step("test", "Run bedwire tests").dependOn(&b.addRunArtifact(tests).step);
}
