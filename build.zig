const std = @import("std");

pub fn build(b: *std.Build) void {
    const version = @import("builtin").zig_version;
    if (comptime version.major != 0 or version.minor != 17 or version.patch != 0) {
        @compileError("bedwire requires Zig 0.17.0");
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

    const bench_protocol = b.dependency("bedrock_protocol", .{ .target = target, .optimize = .fast });
    const bench_bedwire = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = .fast,
        .imports = &.{.{ .name = "bedrock_protocol", .module = bench_protocol.module("bedrock_protocol") }},
    });
    const bench = b.addExecutable(.{ .name = "bedwire-bench", .root_module = b.createModule(.{
        .root_source_file = b.path("bench/main.zig"),
        .target = target,
        .optimize = .fast,
        .imports = &.{.{ .name = "bedwire", .module = bench_bedwire }},
    }) });
    b.step("bench", "Run session, framing, compression and crypto benchmarks")
        .dependOn(&b.addRunArtifact(bench).step);
    b.step("bench-build", "Build the benchmark binary without running it")
        .dependOn(&b.addInstallArtifact(bench, .{}).step);

    const baseline = b.addExecutable(.{ .name = "bedwire-baseline", .root_module = b.createModule(.{
        .root_source_file = b.path("bench/baseline.zig"),
        .target = target,
        .optimize = .fast,
        .imports = &.{.{ .name = "bedwire", .module = bench_bedwire }},
    }) });
    b.step("bench-baseline", "Run the bounded session benchmark matrix")
        .dependOn(&b.addRunArtifact(baseline).step);
    b.step("bench-baseline-build", "Build the session benchmark matrix without running it")
        .dependOn(&b.addInstallArtifact(baseline, .{}).step);

    const pool_bench = b.addExecutable(.{ .name = "bedwire-pool-bench", .root_module = b.createModule(.{
        .root_source_file = b.path("bench/pool.zig"),
        .target = target,
        .optimize = .fast,
        .imports = &.{.{ .name = "bedwire", .module = bench_bedwire }},
    }) });
    b.step("bench-pool-build", "Build the pool contention benchmark")
        .dependOn(&b.addInstallArtifact(pool_bench, .{}).step);
    b.step("bench-pool", "Run the pool contention benchmark")
        .dependOn(&b.addRunArtifact(pool_bench).step);

    if (b.option([]const u8, "libdeflate-path", "libdeflate source directory for optional codec benchmarks")) |source| {
        const root: std.Build.LazyPath = .{ .cwd_relative = source };
        const libdeflate = b.addLibrary(.{ .name = "bench-libdeflate", .root_module = b.createModule(.{
            .target = target,
            .optimize = .fast,
            .link_libc = true,
        }) });
        libdeflate.root_module.addIncludePath(root);
        libdeflate.root_module.addCSourceFiles(.{ .root = root, .files = &.{
            "lib/adler32.c",         "lib/crc32.c",            "lib/deflate_compress.c", "lib/deflate_decompress.c",
            "lib/gzip_compress.c",   "lib/gzip_decompress.c",  "lib/utils.c",            "lib/zlib_compress.c",
            "lib/zlib_decompress.c", "lib/arm/cpu_features.c", "lib/x86/cpu_features.c",
        }, .flags = &.{ "-O2", "-std=c11" } });
        const codecs = b.addExecutable(.{ .name = "bedwire-codecs", .root_module = b.createModule(.{
            .root_source_file = b.path("bench/codecs.zig"),
            .target = target,
            .optimize = .fast,
            .link_libc = true,
            .imports = &.{
                .{ .name = "bedwire", .module = bench_bedwire },
                .{ .name = "interop", .module = b.createModule(.{
                    .root_source_file = b.path("tests/compression/interop.zig"),
                    .imports = &.{.{ .name = "bedwire", .module = bench_bedwire }},
                }) },
            },
        }) });
        codecs.root_module.linkLibrary(libdeflate);
        codecs.root_module.addIncludePath(root);
        codecs.root_module.addCSourceFile(.{ .file = b.path("bench/libdeflate_metrics.c"), .flags = &.{ "-O2", "-std=c11" } });
        b.step("bench-codecs-build", "Build optional raw codec comparisons")
            .dependOn(&b.addInstallArtifact(codecs, .{}).step);
        b.step("bench-codecs", "Run optional raw codec comparisons")
            .dependOn(&b.addRunArtifact(codecs).step);
    }

    const interop = b.addExecutable(.{ .name = "interop-export", .root_module = b.createModule(.{
        .root_source_file = b.path("tools/interop/export.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "bedwire", .module = bedwire }},
    }) });
    b.step("interop", "Build the Snappy exporter used by tools/interop/check.py")
        .dependOn(&b.addInstallArtifact(interop, .{}).step);
}
