const std = @import("std");
const parser = @import("parser.zig");
const assembler = @import("assembler.zig");
const vm = @import("vm.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var stdout_buffer: [1024]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    var stdin = std.fs.File.stdin().deprecatedReader();

    try stdout.print("ampl repl. enter statements ending with ';'. type :q or :quit to exit.\n", .{});

    while (true) {
        try stdout.print("ampl> ", .{});
        try stdout.flush();

        const line_opt = try stdin.readUntilDelimiterOrEofAlloc(allocator, '\n', 4096);
        if (line_opt == null) break;
        const line = line_opt.?;
        defer allocator.free(line);

        const trimmed = std.mem.trim(u8, line, " \t\r\n");
        if (trimmed.len == 0) continue;
        if (std.mem.eql(u8, trimmed, ":q") or std.mem.eql(u8, trimmed, ":quit")) break;

        const tokens = parser.lex(allocator, trimmed) catch |err| {
            try stdout.print("lex error: {s}\n", .{@errorName(err)});
            continue;
        };
        defer allocator.free(tokens);

        var p = parser.Parser.init(allocator, tokens) catch |err| {
            try stdout.print("parser init error: {s}\n", .{@errorName(err)});
            continue;
        };
        defer p.deinit();

        const stmts = p.parse() catch |err| {
            try stdout.print("parse error: {s}\n", .{@errorName(err)});
            continue;
        };
        defer {
            for (stmts) |stmt| stmt.deinit(allocator);
            allocator.free(stmts);
        }

        var assembler_ctx = assembler.Assembler.init(allocator, stmts) catch |err| {
            try stdout.print("assembler init error: {s}\n", .{@errorName(err)});
            continue;
        };
        defer assembler_ctx.deinit();

        const code = assembler_ctx.compile() catch |err| {
            try stdout.print("assemble error: {s}\n", .{@errorName(err)});
            continue;
        };
        defer allocator.free(code);

        var machine = vm.VM.init(allocator) catch |err| {
            try stdout.print("vm init error: {s}\n", .{@errorName(err)});
            continue;
        };
        defer machine.deinit();

        const pid = machine.spawn(code, 0) catch |err| {
            try stdout.print("vm spawn error: {s}\n", .{@errorName(err)});
            continue;
        };

        machine.run() catch |err| {
            try stdout.print("vm run error: {s}\n", .{@errorName(err)});
            continue;
        };

        const vars = assembler_ctx.variables();
        if (vars.len == 0) {
            try stdout.print("(program produced no named variables)\n", .{});
            continue;
        }

        for (vars) |name| {
            const reg = assembler_ctx.registerFor(name) orelse continue;
            const value = machine.readRegister(pid, reg) catch |err| {
                try stdout.print("{s}: read error: {s}\n", .{ name, @errorName(err) });
                continue;
            };

            try stdout.print("{s} = ", .{name});
            try printValue(value, stdout);
            try stdout.print("\n", .{});
        }
    }
}

fn printValue(value: vm.Value, writer: anytype) !void {
    switch (value) {
        .int => |v| try writer.print("{d}", .{v}),
        .pid => |pid| try writer.print("pid({})", .{pid}),
        .unit => try writer.print("()", .{}),
    }
}
