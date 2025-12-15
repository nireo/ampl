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
    var script_path: ?[]const u8 = null;
    for (args[1..]) |arg| {
        if (std.mem.eql(u8, arg, "--dump-code") or std.mem.eql(u8, arg, "-dc")) {
            dump_code = true;
        }

        if (std.mem.eql(u8, arg, "--dump-ast") or std.mem.eql(u8, arg, "-da")) {
            dump_ast = true;
        }

        if (arg.len > 0 and arg[0] != '-') {
            if (script_path == null) {
                script_path = arg;
            }
        }
    }

    var var_ctx = try assembler.VarContext.init(allocator);
    defer var_ctx.deinit();

    var values = std.StringHashMapUnmanaged(vm.Value){};
    defer values.deinit(allocator);

    if (script_path) |path| {
        const source = try std.fs.cwd().readFileAlloc(allocator, path, 10 * 1024 * 1024);
        defer allocator.free(source);

        const trimmed = std.mem.trim(u8, source, " \t\r\n");
        if (trimmed.len == 0) return;
        try handleSource(allocator, stdout, trimmed, dump_code, dump_ast, &var_ctx, &values, false);
        try stdout.flush();
        return;
    }

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

        handleSource(allocator, stdout, trimmed, dump_code, dump_ast, &var_ctx, &values, true) catch {};
    }
}

fn handleSource(
    allocator: std.mem.Allocator,
    stdout: anytype,
    source: []const u8,
    dump_code: bool,
    dump_ast: bool,
    var_ctx: *assembler.VarContext,
    values: *std.StringHashMapUnmanaged(vm.Value),
    emit_results: bool,
) !void {
    const tokens = parser.lex(allocator, source) catch |err| {
        try stdout.print("lex error: {s}\n", .{@errorName(err)});
        return;
    };
    defer allocator.free(tokens);

    var p = parser.Parser.init(allocator, tokens) catch |err| {
        try stdout.print("parser init error: {s}\n", .{@errorName(err)});
        return;
    };
    defer p.deinit();

    const stmts = p.parse() catch |err| {
        try stdout.print("parse error: {s}\n", .{@errorName(err)});
        return;
    };
    defer {
        for (stmts) |stmt| stmt.deinit(allocator);
        allocator.free(stmts);
    }

    if (dump_ast) {
        try stdout.print("ast:\n", .{});
        try parser.dumpStatements(stmts, stdout);
        try stdout.print("\n", .{});
    }

    var assembler_ctx = assembler.Assembler.initWithContext(allocator, stmts, var_ctx) catch |err| {
        try stdout.print("assembler init error: {s}\n", .{@errorName(err)});
        return;
    };
    defer assembler_ctx.deinit();

    var program = assembler_ctx.compile() catch |err| {
        try stdout.print("assemble error: {s}\n", .{@errorName(err)});
        return;
    };
    defer program.deinit(allocator);

    if (dump_code) {
        try stdout.print("code:\n", .{});
        try dumpInstructions(program.code, stdout);
        try stdout.print("\n", .{});
    }

    var machine = vm.VM.init(allocator) catch |err| {
        try stdout.print("vm init error: {s}\n", .{@errorName(err)});
        return;
    };
    defer machine.deinit();

    const pid = machine.spawn(program.toVM(), 0) catch |err| {
        try stdout.print("vm spawn error: {s}\n", .{@errorName(err)});
        return;
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
        return;
    };

    if (emit_results) {
        if (assembler_ctx.lastExprRegister()) |last_reg| {
            const value = machine.readRegister(pid, last_reg) catch |err| {
                try stdout.print("(result read error: {s})\n", .{@errorName(err)});
                return;
            };
            try stdout.print("= ", .{});
            try value.print(&machine.heap, program.atoms, stdout);
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
            try value.print(&machine.heap, program.atoms, stdout);
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
