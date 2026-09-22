const std = @import("std");
const Limits = @import("../limits.zig").Limits;
const flate = @import("../compression/flate.zig");
const snappy = @import("../compression/snappy.zig");

pub const PoolConfig = struct {
    rx_slots: u8,
    tx_slots: u8,

    pub fn conservative() PoolConfig {
        return .{ .rx_slots = 2, .tx_slots = 1 };
    }
};

pub const RxSlot = struct {
    epoch: std.atomic.Value(u64) = .init(0),
    frame: []u8,
    batch: []u8,
    history: [flate.history_len]u8 = undefined,
};

pub const TxSlot = struct {
    epoch: std.atomic.Value(u64) = .init(0),
    assembly: []u8,
    egress: []u8,
    history: [flate.history_len]u8 = undefined,
    table: snappy.Table = undefined,
};

/// Shared bounded RX/TX pool. Keep its address stable and destroy it after all
/// sessions and leases; releasing a token invalidates slices into its slot.
pub const BufferPool = struct {
    allocator: std.mem.Allocator,
    limits: Limits,
    config: PoolConfig,

    rx_slots: []RxSlot,
    tx_slots: []TxSlot,
    rx_storage: []u8,
    tx_storage: []u8,

    rx_free: std.atomic.Value(u64),
    tx_free: std.atomic.Value(u64),
    rx_all_mask: u64,
    tx_all_mask: u64,

    pub fn init(allocator: std.mem.Allocator, limits: Limits, config: PoolConfig) !BufferPool {
        try limits.validate();

        if (config.rx_slots < 1 or config.rx_slots > 64) return error.InvalidLimits;
        if (config.tx_slots < 1 or config.tx_slots > 64) return error.InvalidLimits;

        const per_rx_storage = std.math.add(usize, limits.max_frame_bytes, limits.max_batch_bytes) catch return error.LimitExceeded;
        const total_rx_storage = std.math.mul(usize, per_rx_storage, config.rx_slots) catch return error.LimitExceeded;

        const per_tx_storage = std.math.add(usize, limits.max_frame_bytes, limits.max_batch_bytes) catch return error.LimitExceeded;
        const total_tx_storage = std.math.mul(usize, per_tx_storage, config.tx_slots) catch return error.LimitExceeded;

        const rx_slots = try allocator.alloc(RxSlot, config.rx_slots);
        errdefer allocator.free(rx_slots);

        const tx_slots = try allocator.alloc(TxSlot, config.tx_slots);
        errdefer allocator.free(tx_slots);

        const rx_storage = try allocator.alloc(u8, total_rx_storage);
        errdefer allocator.free(rx_storage);

        const tx_storage = try allocator.alloc(u8, total_tx_storage);
        errdefer allocator.free(tx_storage);

        for (rx_slots, 0..) |*slot, i| {
            const offset = i * per_rx_storage;
            slot.* = .{
                .epoch = .init(0),
                .frame = rx_storage[offset .. offset + limits.max_frame_bytes],
                .batch = rx_storage[offset + limits.max_frame_bytes .. offset + per_rx_storage],
            };
        }

        for (tx_slots, 0..) |*slot, i| {
            const offset = i * per_tx_storage;
            slot.* = .{
                .epoch = .init(0),
                .assembly = tx_storage[offset .. offset + limits.max_batch_bytes],
                .egress = tx_storage[offset + limits.max_batch_bytes .. offset + per_tx_storage],
            };
        }

        const rx_all_mask = maskForSlots(config.rx_slots);
        const tx_all_mask = maskForSlots(config.tx_slots);

        return .{
            .allocator = allocator,
            .limits = limits,
            .config = config,
            .rx_slots = rx_slots,
            .tx_slots = tx_slots,
            .rx_storage = rx_storage,
            .tx_storage = tx_storage,
            .rx_free = .init(rx_all_mask),
            .tx_free = .init(tx_all_mask),
            .rx_all_mask = rx_all_mask,
            .tx_all_mask = tx_all_mask,
        };
    }

    pub const RxToken = struct {
        slot_index: u8,
        epoch: u64,
    };

    pub const TxToken = struct {
        slot_index: u8,
        epoch: u64,
    };

    pub fn deinit(self: *BufferPool) void {
        std.debug.assert(self.rx_free.load(.acquire) == self.rx_all_mask);
        std.debug.assert(self.tx_free.load(.acquire) == self.tx_all_mask);

        self.allocator.free(self.rx_storage);
        self.allocator.free(self.tx_storage);
        self.allocator.free(self.rx_slots);
        self.allocator.free(self.tx_slots);
        self.* = undefined;
    }

    pub fn isIdle(self: *const BufferPool) bool {
        return self.rx_free.load(.acquire) == self.rx_all_mask and
            self.tx_free.load(.acquire) == self.tx_all_mask;
    }

    pub fn acquireRx(self: *BufferPool) error{PoolExhausted}!RxToken {
        const token = try self.acquireSlot(true);
        return .{ .slot_index = token.slot_index, .epoch = token.epoch };
    }

    pub fn acquireTx(self: *BufferPool) error{PoolExhausted}!TxToken {
        const token = try self.acquireSlot(false);
        return .{ .slot_index = token.slot_index, .epoch = token.epoch };
    }

    pub fn releaseRx(self: *BufferPool, token: RxToken) void {
        self.releaseSlot(true, token.slot_index, token.epoch);
    }

    pub fn releaseTx(self: *BufferPool, token: TxToken) void {
        self.releaseSlot(false, token.slot_index, token.epoch);
    }

    pub fn getRx(self: *BufferPool, token: RxToken) ?*RxSlot {
        if (token.slot_index >= self.config.rx_slots) return null;
        const slot = &self.rx_slots[token.slot_index];
        if (slot.epoch.load(.acquire) != token.epoch) return null;
        return slot;
    }

    pub fn getTx(self: *BufferPool, token: TxToken) ?*TxSlot {
        if (token.slot_index >= self.config.tx_slots) return null;
        const slot = &self.tx_slots[token.slot_index];
        if (slot.epoch.load(.acquire) != token.epoch) return null;
        return slot;
    }

    pub fn totalBytes(self: *const BufferPool) usize {
        return self.rx_storage.len + self.tx_storage.len +
            (self.rx_slots.len * @sizeOf(RxSlot)) +
            (self.tx_slots.len * @sizeOf(TxSlot));
    }

    pub fn storageBytes(self: *const BufferPool) usize {
        return self.rx_storage.len + self.tx_storage.len;
    }

    const InternalToken = struct {
        slot_index: u8,
        epoch: u64,
    };

    fn acquireSlot(self: *BufferPool, is_rx: bool) error{PoolExhausted}!InternalToken {
        const free_mask = if (is_rx) &self.rx_free else &self.tx_free;
        const num_slots = if (is_rx) self.config.rx_slots else self.config.tx_slots;

        var current = free_mask.load(.monotonic);
        while (true) {
            if (current == 0) return error.PoolExhausted;

            const idx: u8 = @intCast(@ctz(current));
            if (idx >= num_slots) return error.PoolExhausted;

            const bit = @as(u64, 1) << @intCast(idx);
            const next = current & ~bit;

            if (free_mask.cmpxchgWeak(current, next, .acq_rel, .monotonic)) |stale| {
                current = stale;
            } else {
                const epoch = if (is_rx)
                    self.rx_slots[idx].epoch.load(.acquire)
                else
                    self.tx_slots[idx].epoch.load(.acquire);

                return .{
                    .slot_index = idx,
                    .epoch = epoch,
                };
            }
        }
    }

    fn releaseSlot(self: *BufferPool, is_rx: bool, slot_index: u8, epoch: u64) void {
        const num_slots = if (is_rx) self.config.rx_slots else self.config.tx_slots;
        if (slot_index >= num_slots) return;

        const free_mask = if (is_rx) &self.rx_free else &self.tx_free;
        const epoch_ptr = if (is_rx)
            &self.rx_slots[slot_index].epoch
        else
            &self.tx_slots[slot_index].epoch;

        if (epoch_ptr.cmpxchgStrong(epoch, epoch +% 1, .acq_rel, .monotonic)) |_| {
            return;
        }

        const bit = @as(u64, 1) << @intCast(slot_index);
        _ = free_mask.fetchOr(bit, .release);
    }

    fn maskForSlots(slots: u8) u64 {
        if (slots == 64) return std.math.maxInt(u64);
        return (@as(u64, 1) << @intCast(slots)) - 1;
    }
};
