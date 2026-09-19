const std = @import("std");

pub fn build(b: *std.Build) void {
    const version = @import("builtin").zig_version;
    if (comptime version.major != 0 or version.minor != 16 or version.patch != 0) {
        @compileError("bedwire requires Zig 0.16.0");
    }

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const fuzz_iterations = b.option(usize, "fuzz-iterations", "Deterministic malformed inputs per campaign") orelse 20_000;

    const options = b.addOptions();
    options.addOption(usize, "fuzz_iterations", fuzz_iterations);

    const protocol = b.dependency("bedrock_protocol", .{ .target = target, .optimize = optimize });
    const protocol_module = protocol.module("bedrock_protocol");

    const bedwire = b.addModule("bedwire", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "bedrock_protocol", .module = protocol_module }},
    });
    b.installArtifact(b.addLibrary(.{ .name = "bedwire", .root_module = bedwire }));

    const unit_tests = b.addTest(.{ .root_module = bedwire });

    const suite = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("tests/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "bedwire", .module = bedwire },
            .{ .name = "bedrock_protocol", .module = protocol_module },
            .{ .name = "build_options", .module = options.createModule() },
        },
    }) });

    const test_step = b.step("test", "Run unit, adversarial and deterministic fuzz tests");
    test_step.dependOn(&b.addRunArtifact(unit_tests).step);
    test_step.dependOn(&b.addRunArtifact(suite).step);

    const bench_bedwire = b.addModule("bedwire_bench_lib", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = .ReleaseFast,
        .imports = &.{.{ .name = "bedrock_protocol", .module = protocol_module }},
    });
    const bench = b.addExecutable(.{ .name = "bedwire-bench", .root_module = b.createModule(.{
        .root_source_file = b.path("bench/main.zig"),
        .target = target,
        .optimize = .ReleaseFast,
        .imports = &.{.{ .name = "bedwire", .module = bench_bedwire }},
    }) });
    b.step("bench", "Run session, framing, compression and crypto benchmarks")
        .dependOn(&b.addRunArtifact(bench).step);
    b.step("bench-build", "Build the benchmark binary without running it")
        .dependOn(&b.addInstallArtifact(bench, .{}).step);
}
