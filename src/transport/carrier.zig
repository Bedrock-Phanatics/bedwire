/// Carrier must provide receive(*Self) ![]const u8, send(*Self, []const u8) !void,
/// and close(*Self) void. Delivery must be reliable and ordered. send must consume
/// or copy bytes before returning; receive borrows until the next carrier call.
pub fn validate(comptime T: type) void {
    for (.{ "receive", "send", "close" }) |name| {
        if (!@hasDecl(T, name)) @compileError("Carrier missing " ++ name);
    }
}

/// Instantiate with nethernet.Connection. The application owns its lifetime and IO.
pub fn NetherNet(comptime T: type) type {
    return struct {
        connection: *T,
        pub fn receive(self: *@This()) ![]const u8 {
            const message = try self.connection.receive();
            if (message.reliability != .reliable) return error.UnreliableCarrier;
            return message.data;
        }
        pub fn send(self: *@This(), bytes: []const u8) !void {
            try self.connection.send(bytes, .reliable);
        }
        pub fn close(self: *@This()) void {
            self.connection.close();
        }
    };
}
