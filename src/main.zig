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

    var args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var dump_code = false;
    var dump_ast = false;
    for (args[1..]) |arg| {
        if (std.mem.eql(u8, arg, "--dump-code") or std.mem.eql(u8, arg, "-dc")) {
            dump_code = true;
        }

        if (std.mem.eql(u8, arg, "--dump-ast") or std.mem.eql(u8, arg, "-da")) {
            dump_ast = true;
        }
    }

    var var_ctx = try assembler.VarContext.init(allocator);
    defer var_ctx.deinit();

    var values = std.StringHashMapUnmanaged(vm.Value){};
    defer values.deinit(allocator);

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

        if (dump_ast) {
            try stdout.println("ast:\n", .{});
            try parser.dumpStatements(stmts, stdout);
            try stdout.println("\n", .{});
        }

        var assembler_ctx = assembler.Assembler.initWithContext(allocator, stmts, &var_ctx) catch |err| {
            try stdout.print("assembler init error: {s}\n", .{@errorName(err)});
            continue;
        };
        defer assembler_ctx.deinit();

        var program = assembler_ctx.compile() catch |err| {
            try stdout.print("assemble error: {s}\n", .{@errorName(err)});
            continue;
        };
        defer program.deinit(allocator);

        if (dump_code) {
            try stdout.print("code:\n", .{});
            try dumpInstructions(program.code, stdout);
            try stdout.print("\n", .{});
        }

        var machine = vm.VM.init(allocator) catch |err| {
            try stdout.print("vm init error: {s}\n", .{@errorName(err)});
            continue;
        };
        defer machine.deinit();

        const pid = machine.spawn(program.toVM(), 0) catch |err| {
            try stdout.print("vm spawn error: {s}\n", .{@errorName(err)});
            continue;
        };

        // hydrate registers for known variables
        const var_names = assembler_ctx.variables();
        if (machine.processes.items[pid]) |*proc| {
            for (var_names) |name| {
                if (assembler_ctx.registerFor(name)) |reg| {
                    if (values.get(name)) |val| {
                        proc.regs[reg] = val;
                    }
                }
            }
        }

        machine.run() catch |err| {
            try stdout.print("vm run error: {s}\n", .{@errorName(err)});
            continue;
        };

        if (assembler_ctx.lastExprRegister()) |last_reg| {
            const value = machine.readRegister(pid, last_reg) catch |err| {
                try stdout.print("(result read error: {s})\n", .{@errorName(err)});
                continue;
            };
            try stdout.print("= ", .{});
            try value.print(&machine.heap, stdout);
            try stdout.print("\n", .{});
        }

        for (var_names) |name| {
            const reg = assembler_ctx.registerFor(name) orelse continue;
            const value = machine.readRegister(pid, reg) catch |err| {
                try stdout.print("{s}: read error: {s}\n", .{ name, @errorName(err) });
                continue;
            };

            // persist value for next REPL iteration
            _ = values.put(allocator, name, value) catch {
                try stdout.print("{s}: persist error\n", .{name});
            };

            try stdout.print("{s} = ", .{name});
            try value.print(&machine.heap, stdout);
            try stdout.print("\n", .{});
        }
    }
}

fn dumpInstructions(code: []const vm.Instr, writer: anytype) !void {
    for (code, 0..) |instr, idx| {
        try writer.print("{d}: {s} {d} {d} {d}\n", .{
            idx,
            @tagName(instr.op),
            instr.a,
            instr.b,
            instr.c,
        });
    }
}
