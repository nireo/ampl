const std = @import("std");
const parser = @import("parser.zig");
const vm = @import("vm.zig");

pub const AssembleError = error{
    UnsupportedStatement,
    UnsupportedExpression,
    UnknownIdentifier,
    UnsupportedOperator,
    RegisterOverflow,
    NumberOutOfRange,
} || std.mem.Allocator.Error;

pub const Assembler = struct {
    alloc: std.mem.Allocator,
    instr: std.ArrayList(vm.Instr),
    statements: []*parser.Statement,
    var_regs: std.StringHashMapUnmanaged(u8),
    var_names: std.ArrayList([]const u8),
    next_reg: u8,
    instructions_moved: bool,

    pub fn init(alloc: std.mem.Allocator, statements: []*parser.Statement) !Assembler {
        return .{
            .alloc = alloc,
            .statements = statements,
            .instr = try std.ArrayList(vm.Instr).initCapacity(alloc, 0),
            .var_regs = .{},
            .var_names = try std.ArrayList([]const u8).initCapacity(alloc, 0),
            .next_reg = 0,
            .instructions_moved = false,
        };
    }

    pub fn deinit(self: *Assembler) void {
        for (self.var_names.items) |name| {
            self.alloc.free(name);
        }
        self.var_names.deinit(self.alloc);
        self.var_regs.deinit(self.alloc);

        if (!self.instructions_moved) {
            self.instr.deinit(self.alloc);
        }
    }

    /// compile tries to convert all the statements parsed by the parser into a list of instructions for
    /// the vm. The caller must free the instructions.
    pub fn compile(self: *Assembler) ![]vm.Instr {
        for (self.statements) |stmt| try self.compileStatement(stmt);
        try self.instr.append(self.alloc, .{ .op = .halt, .a = 0, .b = 0, .c = 0 });

        const code = try self.instr.toOwnedSlice(self.alloc);
        self.instructions_moved = true;
        return code;
    }

    fn compileStatement(self: *Assembler, stmt: *parser.Statement) AssembleError!void {
        switch (stmt.*) {
            .expression => {
                _ = try self.compileExpr(stmt.expression.expr);
            },
            .block => {
                for (stmt.block.stmts) |s| {
                    try self.compileStatement(s);
                }
            },
            .if_stmt => try self.compileIfStatement(stmt),
            else => return AssembleError.UnsupportedStatement,
        }
    }

    fn compileExpr(self: *Assembler, expr: *parser.Expr) AssembleError!u8 {
        return switch (expr.*) {
            .number => try self.loadNumber(expr.number),
            .identifier => try self.lookupRegister(expr.identifier),
            .assign => try self.compileAssign(expr.assign.name, expr.assign.value),
            .binary => try self.compileBinary(expr.binary.left, expr.binary.operator, expr.binary.right),
            else => AssembleError.UnsupportedExpression,
        };
    }

    fn compileIfStatement(self: *Assembler, stmt: *parser.Statement) AssembleError!void {
        const ifs = &stmt.if_stmt;
        const dest = try self.compileExpr(ifs.expr);
        const zero_reg = try self.loadNumber(0);

        // compare condition register against zero to set the condition code
        try self.instr.append(self.alloc, .{ .op = .eq, .a = dest, .b = zero_reg, .c = 0 });

        // jump to then branch if condition code is not set (i.e. condition != 0)
        const jmp_not_idx = self.instr.items.len;
        try self.instr.append(self.alloc, .{ .op = .jmp_not, .a = 0, .b = 0, .c = 0 });

        if (ifs.else_branch) |else_branch| {
            try self.compileStatement(else_branch);

            const jmp_end_idx = self.instr.items.len;
            try self.instr.append(self.alloc, .{ .op = .jmp, .a = 0, .b = 0, .c = 0 });

            const then_start = self.instr.items.len;
            try self.compileStatement(ifs.then_branch);

            const end_idx = self.instr.items.len;
            self.instr.items[jmp_not_idx].a = @intCast(then_start);
            self.instr.items[jmp_end_idx].a = @intCast(end_idx);
        } else {
            const skip_then_idx = self.instr.items.len;
            try self.instr.append(self.alloc, .{ .op = .jmp, .a = 0, .b = 0, .c = 0 });

            const then_start = self.instr.items.len;
            try self.compileStatement(ifs.then_branch);

            const end_idx = self.instr.items.len;
            self.instr.items[jmp_not_idx].a = @intCast(then_start);
            self.instr.items[skip_then_idx].a = @intCast(end_idx);
        }
    }

    fn compileAssign(self: *Assembler, name: []const u8, value: *parser.Expr) AssembleError!u8 {
        const dest = try self.getOrCreateRegister(name);
        const value_reg = try self.compileExpr(value);

        if (value_reg != dest) {
            try self.instr.append(self.alloc, .{ .op = .mov, .a = dest, .b = value_reg, .c = 0 });
        }

        return dest;
    }

    fn compileBinary(self: *Assembler, left: *parser.Expr, operator: parser.TokenTag, right: *parser.Expr) AssembleError!u8 {
        const lhs_reg = try self.compileExpr(left);
        const rhs_reg = try self.compileExpr(right);
        const out = try self.allocateRegister();

        const op = switch (operator) {
            .plus => vm.Op.add,
            .minus => vm.Op.sub,
            else => return AssembleError.UnsupportedOperator,
        };

        try self.instr.append(self.alloc, .{ .op = op, .a = out, .b = lhs_reg, .c = rhs_reg });
        return out;
    }

    fn loadNumber(self: *Assembler, value: i64) AssembleError!u8 {
        if (value < 0 or value > std.math.maxInt(u8)) return AssembleError.NumberOutOfRange;
        const reg = try self.allocateRegister();
        try self.instr.append(self.alloc, .{ .op = vm.Op.imm, .a = reg, .b = @as(u8, @intCast(value)), .c = 0 });
        return reg;
    }

    fn lookupRegister(self: *Assembler, name: []const u8) AssembleError!u8 {
        if (self.var_regs.get(name)) |idx| return idx;
        return AssembleError.UnknownIdentifier;
    }

    fn getOrCreateRegister(self: *Assembler, name: []const u8) AssembleError!u8 {
        if (self.var_regs.get(name)) |idx| return idx;

        const reg = try self.allocateRegister();
        const duped = try self.alloc.dupe(u8, name);
        errdefer self.alloc.free(duped);

        try self.var_regs.put(self.alloc, duped, reg);
        try self.var_names.append(self.alloc, duped);
        return reg;
    }

    fn allocateRegister(self: *Assembler) AssembleError!u8 {
        const reg = self.next_reg;
        if (reg == std.math.maxInt(u8)) return AssembleError.RegisterOverflow;
        self.next_reg +%= 1;
        return reg;
    }

    /// variables returns the list of variable names that were bound to registers.
    /// The returned slice is owned by the assembler and becomes invalid after deinit.
    pub fn variables(self: *const Assembler) []const []const u8 {
        return self.var_names.items;
    }

    /// registerFor returns the register index for a variable name when present.
    pub fn registerFor(self: *const Assembler, name: []const u8) ?u8 {
        return self.var_regs.get(name);
    }
};

const testing = std.testing;

test "assemble simple addition assignment" {
    const src = "a = 2 + 3;";
    const tokens = try parser.lex(testing.allocator, src);
    defer testing.allocator.free(tokens);

    var p = try parser.Parser.init(testing.allocator, tokens);
    defer p.deinit();

    const stmts = try p.parse();
    defer {
        for (stmts) |stmt| stmt.deinit(testing.allocator);
        testing.allocator.free(stmts);
    }

    var assembler = try Assembler.init(testing.allocator, stmts);
    defer assembler.deinit();

    const code = try assembler.compile();
    defer testing.allocator.free(code);

    try testing.expectEqual(@as(usize, 5), code.len);
    try testing.expect(code[0].op == .imm);
    try testing.expect(code[1].op == .imm);
    try testing.expect(code[2].op == .add);
    try testing.expect(code[3].op == .mov);
    try testing.expect(code[4].op == .halt);

    var machine = try vm.VM.init(testing.allocator);
    defer machine.deinit();

    const pid = try machine.spawn(code, 0);
    try machine.run();

    const proc = machine.processes.items[pid].?;
    switch (proc.regs[0]) {
        .int => |val| try testing.expectEqual(@as(i64, 5), val),
        else => try testing.expect(false),
    }
}

test "if statement executes then branch" {
    const src = "a = 0; if (1) { a = 2; } else { a = 3; }";
    const tokens = try parser.lex(testing.allocator, src);
    defer testing.allocator.free(tokens);

    var p = try parser.Parser.init(testing.allocator, tokens);
    defer p.deinit();

    const stmts = try p.parse();
    defer {
        for (stmts) |stmt| stmt.deinit(testing.allocator);
        testing.allocator.free(stmts);
    }

    var assembler = try Assembler.init(testing.allocator, stmts);
    defer assembler.deinit();

    const code = try assembler.compile();
    defer testing.allocator.free(code);

    var machine = try vm.VM.init(testing.allocator);
    defer machine.deinit();

    const pid = try machine.spawn(code, 0);
    try machine.run();

    const proc = machine.processes.items[pid].?;
    switch (proc.regs[0]) {
        .int => |val| try testing.expectEqual(@as(i64, 2), val),
        else => try testing.expect(false),
    }
}

test "if statement skips then without else" {
    const src = "a = 0; if (0) { a = 5; }";
    const tokens = try parser.lex(testing.allocator, src);
    defer testing.allocator.free(tokens);

    var p = try parser.Parser.init(testing.allocator, tokens);
    defer p.deinit();

    const stmts = try p.parse();
    defer {
        for (stmts) |stmt| stmt.deinit(testing.allocator);
        testing.allocator.free(stmts);
    }

    var assembler = try Assembler.init(testing.allocator, stmts);
    defer assembler.deinit();

    const code = try assembler.compile();
    defer testing.allocator.free(code);

    var machine = try vm.VM.init(testing.allocator);
    defer machine.deinit();

    const pid = try machine.spawn(code, 0);
    try machine.run();

    const proc = machine.processes.items[pid].?;
    switch (proc.regs[0]) {
        .int => |val| try testing.expectEqual(@as(i64, 0), val),
        else => try testing.expect(false),
    }
}
