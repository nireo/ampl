const std = @import("std");
const parser = @import("parser.zig");
const vm = @import("vm.zig");

pub const AssembleError = error{
    UnsupportedStatement,
    UnsupportedExpression,
    UnknownIdentifier,
    UnknownFunction,
    DuplicateFunction,
    UnsupportedOperator,
    RegisterOverflow,
    NumberOutOfRange,
    WrongAmountOfArguments,
} || std.mem.Allocator.Error;

/// VarContext constains all of the varialbes in a given context. It is mainly used to keep track of
/// registers
pub const VarContext = struct {
    alloc: std.mem.Allocator,
    entries: std.ArrayList(Entry),
    var_names: std.ArrayList([]const u8),
    next_reg: u8,

    const Entry = struct {
        name: []const u8,
        reg: u8,
    };

    pub fn init(alloc: std.mem.Allocator) !VarContext {
        const ctx = VarContext{
            .alloc = alloc,
            .entries = try std.ArrayList(Entry).initCapacity(alloc, 0),
            .var_names = try std.ArrayList([]const u8).initCapacity(alloc, 0),
            .next_reg = 0,
        };
        return ctx;
    }

    pub fn deinit(self: *VarContext) void {
        for (self.var_names.items) |name| {
            self.alloc.free(name);
        }
        self.var_names.deinit(self.alloc);
        self.entries.deinit(self.alloc);
    }
};

pub const Assembler = struct {
    alloc: std.mem.Allocator,
    instr: std.ArrayList(vm.Instr),
    statements: []*parser.Statement,
    var_ctx: *VarContext,
    current_ctx: *VarContext,
    owned_ctx: ?*VarContext,
    last_expr_reg: ?u8,
    instructions_moved: bool,
    functions: std.StringHashMap(FunctionInfo),
    function_order: std.ArrayList([]const u8),
    call_fixups: std.ArrayList(CallFixup),

    /// FunctionInfo contains the parsed structure of the function and the instruction where it starts
    const FunctionInfo = struct {
        stmt: *parser.Statement,
        start_ip: ?u8 = null,
    };

    const CallFixup = struct {
        instr_idx: usize,
        name: []const u8,
    };

    pub fn init(alloc: std.mem.Allocator, statements: []*parser.Statement) !Assembler {
        const ctx_ptr = try alloc.create(VarContext);
        errdefer alloc.destroy(ctx_ptr);
        ctx_ptr.* = try VarContext.init(alloc);

        return Assembler{
            .alloc = alloc,
            .statements = statements,
            .instr = try std.ArrayList(vm.Instr).initCapacity(alloc, 0),
            .var_ctx = ctx_ptr,
            .current_ctx = ctx_ptr,
            .owned_ctx = ctx_ptr,
            .last_expr_reg = null,
            .instructions_moved = false,
            .functions = std.StringHashMap(FunctionInfo).init(alloc),
            .function_order = try std.ArrayList([]const u8).initCapacity(alloc, 0),
            .call_fixups = try std.ArrayList(CallFixup).initCapacity(alloc, 0),
        };
    }

    /// initWithContext allocates everything the assembler needs and uses an existing context. This is mainly used
    /// such that the repl can have a persistent state over many code lines.
    pub fn initWithContext(alloc: std.mem.Allocator, statements: []*parser.Statement, ctx: *VarContext) !Assembler {
        return .{
            .alloc = alloc,
            .statements = statements,
            .instr = try std.ArrayList(vm.Instr).initCapacity(alloc, 0),
            .var_ctx = ctx,
            .current_ctx = ctx,
            .owned_ctx = null,
            .last_expr_reg = null,
            .instructions_moved = false,
            .functions = std.StringHashMap(FunctionInfo).init(alloc),
            .function_order = try std.ArrayList([]const u8).initCapacity(alloc, 0),
            .call_fixups = try std.ArrayList(CallFixup).initCapacity(alloc, 0),
        };
    }

    /// context returns the current variable context
    fn context(self: *Assembler) *VarContext {
        return self.current_ctx;
    }

    /// deinit frees up the memory that it allocated for itself. It does not free the parsed structures
    pub fn deinit(self: *Assembler) void {
        if (self.owned_ctx) |ctx_ptr| {
            ctx_ptr.deinit();
            self.alloc.destroy(ctx_ptr);
        }

        self.functions.deinit();
        self.function_order.deinit(self.alloc);
        self.call_fixups.deinit(self.alloc);

        if (!self.instructions_moved) {
            self.instr.deinit(self.alloc);
        }
    }

    /// compile tries to convert all the statements parsed by the parser into a list of instructions for
    /// the vm. The caller must free the instructions.
    pub fn compile(self: *Assembler) ![]vm.Instr {
        self.last_expr_reg = null;
        self.functions.clearRetainingCapacity();
        self.function_order.clearRetainingCapacity();
        self.call_fixups.clearRetainingCapacity();
        try self.functions.ensureTotalCapacity(4);

        try self.collectFunctions();

        for (self.statements) |stmt| {
            if (stmt.* == .fn_def) continue; // compiled later
            try self.compileStatement(stmt);
        }
        try self.instr.append(self.alloc, .{ .op = .halt, .a = 0, .b = 0, .c = 0 });

        try self.compileFunctions();
        try self.patchCallTargets();

        const code = try self.instr.toOwnedSlice(self.alloc);
        self.instructions_moved = true;
        return code;
    }

    fn collectFunctions(self: *Assembler) AssembleError!void {
        for (self.statements) |stmt| {
            if (stmt.* != .fn_def) continue;
            const name = stmt.fn_def.name;
            if (self.functions.contains(name)) return AssembleError.DuplicateFunction;

            try self.functions.put(name, .{ .stmt = stmt });
            try self.function_order.append(self.alloc, name);
        }
    }

    fn compileFunctions(self: *Assembler) AssembleError!void {
        for (self.function_order.items) |name| {
            var info = self.functions.getPtr(name) orelse unreachable;
            info.start_ip = @intCast(self.instr.items.len);
            try self.compileFunction(info.stmt);
        }
    }

    fn patchCallTargets(self: *Assembler) AssembleError!void {
        for (self.call_fixups.items) |fixup| {
            const info = self.functions.get(fixup.name) orelse return AssembleError.UnknownFunction;
            const target = info.start_ip orelse return AssembleError.UnknownFunction;
            self.instr.items[fixup.instr_idx].a = target;
        }
    }

    fn compileFunction(self: *Assembler, stmt: *parser.Statement) AssembleError!void {
        const fn_def = &stmt.fn_def;
        var fn_ctx = try VarContext.init(self.alloc);
        defer fn_ctx.deinit();

        for (fn_def.params, 0..) |param, idx| {
            const duped = try fn_ctx.alloc.dupe(u8, param.name);
            errdefer fn_ctx.alloc.free(duped);
            try fn_ctx.entries.append(fn_ctx.alloc, .{
                .name = duped,
                .reg = @intCast(idx),
            });
            try fn_ctx.var_names.append(fn_ctx.alloc, duped);
        }
        fn_ctx.next_reg = @intCast(fn_def.params.len);

        const prev_ctx = self.current_ctx;
        self.current_ctx = &fn_ctx;
        defer self.current_ctx = prev_ctx;

        const prev_last_expr = self.last_expr_reg;
        self.last_expr_reg = null;
        defer self.last_expr_reg = prev_last_expr;

        try self.compileStatement(fn_def.body);

        if (self.instr.items.len == 0 or self.instr.items[self.instr.items.len - 1].op != .ret) {
            try self.instr.append(self.alloc, .{ .op = .ret, .a = 0, .b = 0, .c = 0 });
        }
    }

    fn compileStatement(self: *Assembler, stmt: *parser.Statement) AssembleError!void {
        switch (stmt.*) {
            .expression => {
                const out = try self.compileExpr(stmt.expression.expr);
                if (stmt.expression.expr.* != .assign) {
                    self.last_expr_reg = out;
                }
            },
            .block => {
                for (stmt.block.stmts) |s| {
                    try self.compileStatement(s);
                }
            },
            .fn_def => {},
            .if_stmt => try self.compileIfStatement(stmt),
            .loop => try self.compileLoop(stmt),
            .ret => try self.compileReturn(stmt),
            else => return AssembleError.UnsupportedStatement,
        }
    }

    fn compileExpr(self: *Assembler, expr: *parser.Expr) AssembleError!u8 {
        return switch (expr.*) {
            .number => try self.loadNumber(expr.number),
            .identifier => try self.lookupRegister(expr.identifier),
            .assign => try self.compileAssign(expr.assign.name, expr.assign.value),
            .binary => try self.compileBinary(expr.binary.left, expr.binary.operator, expr.binary.right),
            .function_call => try self.compileFunctionCall(expr.function_call.name, expr.function_call.args),
        };
    }

    fn compileLoop(self: *Assembler, stmt: *parser.Statement) AssembleError!void {
        const lo = &stmt.loop;
        if (lo.cond) |c| {
            const loop_start = self.instr.items.len;
            const dest = try self.compileExpr(c);
            const zero_reg = try self.loadNumber(0);

            // update the condition code
            try self.instr.append(self.alloc, .{ .op = .eq, .a = dest, .b = zero_reg, .c = 0 });

            // if condition is false then jump past the loop. the end of loop is updated later.
            const jmp_false_idx = self.instr.items.len;
            try self.instr.append(self.alloc, .{ .op = .jmp_true, .a = 0, .b = 0, .c = 0 });

            try self.compileStatement(lo.body);

            // go back to start
            try self.instr.append(self.alloc, .{ .op = .jmp, .a = @intCast(loop_start), .b = 0, .c = 0 });

            // jump past the loop if the condition is false
            self.instr.items[jmp_false_idx].a = @intCast(self.instr.items.len);
        } else {
            const loop_start_idx = self.instr.items.len;
            try self.compileStatement(lo.body);

            try self.instr.append(self.alloc, .{ .op = .jmp, .a = @intCast(loop_start_idx), .b = 0, .c = 0 });
        }
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

    fn compileReturn(self: *Assembler, stmt: *parser.Statement) AssembleError!void {
        const ret_stmt = &stmt.ret;
        var ret_reg: u8 = 0;
        if (ret_stmt.value) |val| {
            ret_reg = try self.compileExpr(val);
        }

        try self.instr.append(self.alloc, .{ .op = .ret, .a = ret_reg, .b = 0, .c = 0 });
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
            .lt => vm.Op.lt,
            else => return AssembleError.UnsupportedOperator,
        };

        try self.instr.append(self.alloc, .{ .op = op, .a = out, .b = lhs_reg, .c = rhs_reg });
        return out;
    }

    /// compileRecv compiles the built in recv implementation. We need to specially handle this because
    /// this can't be implemented using the code itself, as it uses the internal mailbox. it takes in the
    /// arguments just to validate that they're isn't any to keep the other functions clean
    fn compileRecv(self: *Assembler, args: []*parser.Expr) AssembleError!u8 {
        if (args.len != 0) return AssembleError.WrongAmountOfArguments;
        const dest_reg = try self.allocateRegister();
        try self.instr.append(self.alloc, .{ .op = .recv, .a = dest_reg, .b = dest_reg, .c = 0 });
        return dest_reg;
    }

    fn compileSend(self: *Assembler, args: []*parser.Expr) AssembleError!u8 {
        if (args.len != 2) return AssembleError.WrongAmountOfArguments;

        const pid_reg = try self.compileExpr(args[0]);
        const payload_reg = try self.compileExpr(args[1]);
        try self.instr.append(self.alloc, .{ .op = .send, .a = pid_reg, .b = payload_reg, .c = 0 });
        return payload_reg;
    }

    fn compileFunctionCall(self: *Assembler, name: []const u8, args: []*parser.Expr) AssembleError!u8 {
        if (std.mem.eql(u8, "recv", name)) return try self.compileRecv(args);
        if (std.mem.eql(u8, "send", name)) return try self.compileSend(args);

        // check if the function exists
        if (!self.functions.contains(name)) return AssembleError.UnknownFunction;

        // compile each argument given to the function
        var compiled_args = try std.ArrayList(u8).initCapacity(self.alloc, args.len);
        defer compiled_args.deinit(self.alloc);

        for (args) |arg| {
            const reg = try self.compileExpr(arg);
            try compiled_args.append(self.alloc, reg);
        }

        var call_regs = try std.ArrayList(u8).initCapacity(self.alloc, args.len);
        defer call_regs.deinit(self.alloc);

        // try to allocate a register for each argument
        for (compiled_args.items) |src| {
            const target = try self.allocateRegister();
            try call_regs.append(self.alloc, target);
            if (target != src) {
                try self.instr.append(self.alloc, .{ .op = .mov, .a = target, .b = src, .c = 0 });
            }
        }

        // try to reuse the first call register for the result of the function
        const dest_reg: u8 = if (call_regs.items.len > 0) call_regs.items[0] else try self.allocateRegister();
        if (call_regs.items.len > std.math.maxInt(u8)) return AssembleError.NumberOutOfRange;
        const arg_count: u8 = @intCast(call_regs.items.len);
        const info = self.functions.get(name).?;

        const instr_idx = self.instr.items.len;
        const target_ip: u8 = if (info.start_ip) |ip| ip else 0;
        try self.instr.append(self.alloc, .{ .op = .call, .a = target_ip, .b = dest_reg, .c = arg_count });

        if (info.start_ip == null) {
            try self.call_fixups.append(self.alloc, .{
                .instr_idx = instr_idx,
                .name = name,
            });
        }

        return dest_reg;
    }

    fn loadNumber(self: *Assembler, value: i64) AssembleError!u8 {
        if (value < 0 or value > std.math.maxInt(u8)) return AssembleError.NumberOutOfRange;
        const reg = try self.allocateRegister();
        try self.instr.append(self.alloc, .{ .op = vm.Op.imm, .a = reg, .b = @as(u8, @intCast(value)), .c = 0 });
        return reg;
    }

    fn lookupRegister(self: *Assembler, name: []const u8) AssembleError!u8 {
        const ctx = self.context();
        for (ctx.entries.items) |entry| {
            if (std.mem.eql(u8, entry.name, name)) return entry.reg;
        }
        return AssembleError.UnknownIdentifier;
    }

    fn getOrCreateRegister(self: *Assembler, name: []const u8) AssembleError!u8 {
        const ctx = self.context();
        for (ctx.entries.items) |entry| {
            if (std.mem.eql(u8, entry.name, name)) return entry.reg;
        }

        const reg = try self.allocateRegister();
        const duped = try ctx.alloc.dupe(u8, name);
        errdefer ctx.alloc.free(duped);

        try ctx.entries.append(ctx.alloc, .{ .name = duped, .reg = reg });
        try ctx.var_names.append(ctx.alloc, duped);
        return reg;
    }

    fn allocateRegister(self: *Assembler) AssembleError!u8 {
        const ctx = self.context();
        const reg = ctx.next_reg;
        if (reg == std.math.maxInt(u8)) return AssembleError.RegisterOverflow;
        ctx.next_reg +%= 1;
        return reg;
    }

    /// variables returns the list of variable names that were bound to registers.
    /// The returned slice is owned by the assembler and becomes invalid after deinit.
    pub fn variables(self: *Assembler) []const []const u8 {
        return self.context().var_names.items;
    }

    /// registerFor returns the register index for a variable name when present.
    pub fn registerFor(self: *Assembler, name: []const u8) ?u8 {
        const ctx = self.context();
        for (ctx.entries.items) |entry| {
            if (std.mem.eql(u8, entry.name, name)) return entry.reg;
        }
        return null;
    }

    /// lastExprRegister returns the register that holds the last pure expression result, when any.
    pub fn lastExprRegister(self: *const Assembler) ?u8 {
        return self.last_expr_reg;
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

test "loop condition drives execution" {
    const src = "a = 1; loop (a < 3) { a = a + 1; }";
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
        .int => |val| try testing.expectEqual(@as(i64, 3), val),
        else => try testing.expect(false),
    }
}

test "function definitions compile and calls preserve caller registers" {
    const src = "def add(a, b) { ret a + b; } x = 5; y = add(x, 7);";
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

    try testing.expect(assembler.registerFor("x") != null);
    try testing.expect(assembler.registerFor("y") != null);
    const x_reg = assembler.registerFor("x").?;
    const y_reg = assembler.registerFor("y").?;

    const x_val = try machine.readRegister(pid, x_reg);
    switch (x_val) {
        .int => |val| try testing.expectEqual(@as(i64, 5), val),
        else => try testing.expect(false),
    }

    const y_val = try machine.readRegister(pid, y_reg);
    switch (y_val) {
        .int => |val| try testing.expectEqual(@as(i64, 12), val),
        else => try testing.expect(false),
    }
}

test "recv compiles to recv opcode" {
    const src = "result = recv();";
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

    try testing.expectEqual(vm.Op.recv, code[0].op);
    try testing.expectEqual(vm.Op.halt, code[code.len - 1].op);
}

test "send compiles to send opcode" {
    const src = "a = 1; b = 2; send(a, b);";
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

    const send_instr = code[4];
    const a_reg = assembler.registerFor("a").?;
    const b_reg = assembler.registerFor("b").?;

    try testing.expectEqual(vm.Op.send, send_instr.op);
    try testing.expectEqual(a_reg, send_instr.a);
    try testing.expectEqual(b_reg, send_instr.b);
    try testing.expectEqual(vm.Op.halt, code[code.len - 1].op);
}
