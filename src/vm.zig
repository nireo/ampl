const std = @import("std");

const HeapHandle = u32;

/// MAX_REGS defines the highest register index encodable in an instruction.
pub const MAX_REGS = 256;

pub const ValueTag = enum {
    int,
    pid,
    unit,
    string,
    atom,
};

pub const Value = union(ValueTag) {
    int: i64,
    pid: usize,
    unit: void,
    string: HeapHandle,
    atom: u16,

    pub fn print(value: Value, heap: ?*const Heap, atoms: ?[]const []const u8, writer: anytype) !void {
        switch (value) {
            .int => |v| try writer.print("{d}", .{v}),
            .pid => |pid| try writer.print("pid({})", .{pid}),
            .unit => try writer.print("()", .{}),
            .string => |handle| {
                if (heap) |h| {
                    if (h.get(handle)) |s| {
                        try writer.print("\"{s}\"", .{s});
                    } else {
                        try writer.print("<freed string {}>", .{handle});
                    }
                } else {
                    try writer.print("<string {}>", .{handle});
                }
            },
            .atom => |atom_id| {
                if (atoms) |slice| {
                    if (atom_id < slice.len) {
                        try writer.print(":{s}", .{slice[atom_id]});
                        return;
                    }
                }
                try writer.print(":{}", .{atom_id});
            },
        }
    }
};

pub const FunctionLayout = struct {
    start_ip: usize,
    register_count: usize,
};

pub const Program = struct {
    code: []const Instr,
    strings: []const []const u8,
    register_count: usize = MAX_REGS,
    functions: []const FunctionLayout = &[_]FunctionLayout{},
    atoms: []const []const u8 = &[_][]const u8{},

    /// registerCountFor returns the register count for a function starting at the
    /// provided instruction pointer.
    pub fn registerCountFor(self: Program, start_ip: usize) usize {
        for (self.functions) |layout| {
            if (layout.start_ip == start_ip) return layout.register_count;
        }
        return self.register_count;
    }
};

const HeapObjectTag = enum {
    string,
};

const HeapObjectData = union(HeapObjectTag) {
    string: []u8,

    pub fn deinit(self: *HeapObjectData, alloc: std.mem.Allocator) void {
        switch (self.*) {
            .string => {
                alloc.free(self.string);
            },
        }
    }
};

const HeapObject = struct {
    marked: bool,
    in_use: bool,
    data: HeapObjectData,
};

pub const Heap = struct {
    allocator: std.mem.Allocator,
    entries: std.ArrayList(HeapObject),

    pub fn init(alloc: std.mem.Allocator) !Heap {
        return .{
            .allocator = alloc,
            .entries = try std.ArrayList(HeapObject).initCapacity(alloc, 16),
        };
    }

    pub fn deinit(self: *Heap) void {
        for (self.entries.items) |*entry| {
            if (entry.in_use) {
                entry.data.deinit(self.allocator);
            }
        }
        self.entries.deinit(self.allocator);
    }

    pub fn allocString(self: *Heap, bytes: []const u8) !HeapHandle {
        const duped = try self.allocator.dupe(u8, bytes);
        errdefer self.allocator.free(duped);

        const data = HeapObjectData{ .string = duped };

        // try to find a free slot first
        for (self.entries.items, 0..) |entry, idx| {
            if (!entry.in_use) {
                self.entries.items[idx] = .{
                    .data = data,
                    .marked = false,
                    .in_use = true,
                };
                return @intCast(idx);
            }
        }

        const idx = self.entries.items.len;
        try self.entries.append(self.allocator, .{
            .data = data,
            .marked = false,
            .in_use = true,
        });
        return @intCast(idx);
    }

    pub fn get(self: *const Heap, handle: HeapHandle) ?[]const u8 {
        const idx: usize = @intCast(handle);
        if (idx >= self.entries.items.len) return null;
        const entry = self.entries.items[idx];
        if (!entry.in_use) return null;
        return entry.data.string;
    }

    /// clearMarks goes through all of the items and sets the marked flag to false.
    pub fn clearMarks(self: *Heap) void {
        for (self.entries.items) |*entry| {
            entry.marked = false;
        }
    }

    /// mark takes in a given heap handle and makes that given item. It doesn't do anything if the heap handle is invalid.
    pub fn mark(self: *Heap, handle: HeapHandle) void {
        const idx: usize = @intCast(handle);
        if (idx >= self.entries.items.len) return;
        const entry = &self.entries.items[idx];
        if (!entry.in_use) return;
        entry.marked = true;
    }

    /// sweep goes through all of the entries and frees their contents if they're not in use and they're marked. If they're not in use
    /// but they're marked then we remove the mark and skip said entry.
    pub fn sweep(self: *Heap) void {
        for (self.entries.items) |*entry| {
            if (!entry.in_use) continue;
            if (entry.marked) {
                entry.marked = false;
                continue;
            }

            entry.data.deinit(self.allocator);
            entry.data = HeapObjectData{ .string = &[_]u8{} };
            entry.marked = false;
            entry.in_use = false;
        }
    }
};

const Message = struct {
    sender: usize,
    payload: Value,
};

const Frame = struct {
    reg_base: usize,
    reg_count: usize,
    cond_code: u8,
    return_ip: usize,
    return_dest: u8,
};

pub const Op = enum(u8) {
    nop,
    mov,
    imm,
    str,
    add,
    sub,
    spawn,
    send,
    jmp,
    call,
    ret,
    self,
    recv,
    halt,
    eq,
    lt,
    gt,
    lteq,
    gteq,
    jmp_true,
    jmp_not,
    print,
    atom,
};

pub const Instr = struct {
    op: Op,
    a: u8,
    b: u8,
    c: u8,

    fn print(self: Instr) void {
        std.debug.print("\t{} {} {} {}\n", .{ self.op, self.a, self.b, self.c });
    }
};

fn debugInstructions(code: []const Instr) void {
    for (code, 0..) |instr, idx| {
        std.debug.print("{}: ", .{idx});
        instr.print();
    }
}

/// Number of instructions a process may execute before it is preempted and
/// returned to the run queue. This is done such that we don't really want to
/// return a process to the run queue after for example executing one add instruction.
const REDUCTIONS_PER_SLICE: usize = 300;

/// A process can ultimately be in a just a few states.
/// - ready to compute something
/// - waiting for something to happen
/// - dead i.e. finished
const ProcessStatus = enum {
    ready,
    waiting,
    dead,
};

/// Process represents a single 'actor' in the runtime. The actors have their own registers
/// which the instructions manipulate; they keep track of condition codes, instruction pointer,
/// code, call frames etc which are very common. Additionally processes have a mailbox, which can
/// be used to receive information from other processes.
const Process = struct {
    id: usize,
    regs: []Value,
    reg_base: usize,
    reg_count: usize,
    reg_stack: std.ArrayList(Value),
    cond_code: u8,
    ip: usize,
    program: Program,
    mailbox: std.ArrayList(Message),
    frames: std.ArrayList(Frame),
    status: ProcessStatus,
};

pub const VM = struct {
    allocator: std.mem.Allocator,
    processes: std.ArrayList(?Process),
    run_queue: std.ArrayList(usize),
    heap: Heap,

    /// init sets up a basic vm with some capacity for processes and a run queue.
    pub fn init(alloc: std.mem.Allocator) !VM {
        return VM{
            .allocator = alloc,
            .processes = try std.ArrayList(?Process).initCapacity(alloc, 128),
            .run_queue = try std.ArrayList(usize).initCapacity(alloc, 128),
            .heap = try Heap.init(alloc),
        };
    }

    /// deinit frees the resources used by the vm
    pub fn deinit(vm: *VM) void {
        // deinit each process
        for (vm.processes.items) |*maybe_proc| {
            if (maybe_proc.*) |*proc| {
                proc.reg_stack.deinit(vm.allocator);
                proc.mailbox.deinit(vm.allocator);
                proc.frames.deinit(vm.allocator);
            }
        }

        // deinit the arrays themselves.
        vm.processes.deinit(vm.allocator);
        vm.run_queue.deinit(vm.allocator);
        vm.heap.deinit();
    }

    /// spawn sets up a new process with some given program and a staring instruction pointer.
    /// It first tries to look for a processor in the list if every processor is taken it adds
    /// a new one to the list. this function also appends the new process to the run queue.
    pub fn spawn(vm: *VM, program: Program, start_ip: usize) !usize {
        // look for some available process; append to array if not found
        var pid: usize = undefined;
        for (vm.processes.items, 0..) |maybe_proc, i| {
            if (maybe_proc == null) {
                pid = i;
                break;
            }
        } else {
            pid = vm.processes.items.len;
            try vm.processes.append(vm.allocator, null);
        }

        if (start_ip >= program.code.len) return error.InvalidStartIp;

        const reg_count: usize = @max(program.register_count, @as(usize, 1));
        var reg_stack = try std.ArrayList(Value).initCapacity(vm.allocator, reg_count);
        errdefer reg_stack.deinit(vm.allocator);
        try reg_stack.resize(vm.allocator, reg_count);
        for (reg_stack.items) |*r| r.* = Value{ .unit = {} };

        // basic process init & run queue append
        const mailbox = std.ArrayList(Message).empty;
        const proc = Process{
            .id = pid,
            .regs = reg_stack.items,
            .reg_base = 0,
            .reg_count = reg_count,
            .reg_stack = reg_stack,
            .cond_code = 0,
            .ip = start_ip,
            .program = program,
            .mailbox = mailbox,
            .frames = std.ArrayList(Frame).empty,
            .status = .ready,
        };

        vm.processes.items[pid] = proc;
        try vm.run_queue.append(vm.allocator, pid);
        return pid;
    }

    /// popNext removes the first elements from the run queue list and then returns that process.
    fn popNext(vm: *VM) ?usize {
        if (vm.run_queue.items.len == 0) return null;
        return vm.run_queue.orderedRemove(0);
    }

    /// run loops through the processes and gives each ready process a slice of
    /// reductions (instruction budget) before re-enqueuing it. Waiting processes
    /// remain parked until a message arrives.
    pub fn run(vm: *VM) !void {
        while (vm.popNext()) |pid| {
            const maybe_proc = &vm.processes.items[pid];
            if (maybe_proc.*) |*proc| {
                if (proc.status != .ready) continue; // skip waiting/dead

                // each process has a set of reductions since we don't want to for example switch between processes
                // every time an 'add' is executed
                var reductions: usize = REDUCTIONS_PER_SLICE;
                while (reductions > 0 and proc.status == .ready) : (reductions -= 1) {
                    try vm.execute(proc);
                }

                // only requeue ready processes that exhausted their slice.
                if (proc.status == .ready and reductions == 0) {
                    try vm.run_queue.append(vm.allocator, pid);
                }
            }
        }
    }

    /// execute executes the next instruction in the processor.
    fn execute(vm: *VM, proc: *Process) !void {
        if (proc.ip >= proc.program.code.len) {
            proc.status = .dead;
            return;
        }

        const instr = proc.program.code[proc.ip];
        switch (instr.op) {
            .nop => {
                proc.ip += 1;
            },
            .mov => {
                proc.regs[instr.a] = proc.regs[instr.b];
                proc.ip += 1;
            },
            .imm => {
                proc.regs[instr.a] = Value{ .int = instr.b };
                proc.ip += 1;
            },
            .str => {
                const idx: usize = instr.b;
                if (idx >= proc.program.strings.len) return error.InvalidStringIndex;
                const handle = try vm.heap.allocString(proc.program.strings[idx]);
                proc.regs[instr.a] = Value{ .string = handle };
                proc.ip += 1;
            },
            .add => {
                const lhs = try expectInt(proc.regs[instr.b]);
                const rhs = try expectInt(proc.regs[instr.c]);
                proc.regs[instr.a] = Value{ .int = lhs + rhs };
                proc.ip += 1;
            },
            .sub => {
                const lhs = try expectInt(proc.regs[instr.b]);
                const rhs = try expectInt(proc.regs[instr.c]);
                proc.regs[instr.a] = Value{ .int = lhs - rhs };
                proc.ip += 1;
            },
            .spawn => {
                const child_ip = @as(usize, instr.b);
                const pid = try vm.spawn(proc.program, child_ip);
                proc.regs[instr.a] = Value{ .pid = pid };
                proc.ip += 1;
            },
            .send => {
                const to_pid = try expectPid(proc.regs[instr.a]);
                const payload = proc.regs[instr.b];
                try vm.sendMessage(proc.id, to_pid, payload);
                proc.ip += 1;
            },
            .eq => {
                const val_a = proc.regs[instr.a];
                const val_b = proc.regs[instr.b];

                proc.cond_code = if (std.meta.eql(val_a, val_b)) 1 else 0;
                proc.ip += 1;
            },
            .lt => {
                const lhs = try expectInt(proc.regs[instr.b]);
                const rhs = try expectInt(proc.regs[instr.c]);
                const is_true = lhs < rhs;
                proc.cond_code = @intCast(@as(u8, @intFromBool(is_true)));
                proc.regs[instr.a] = Value{ .int = if (is_true) 1 else 0 };
                proc.ip += 1;
            },
            .gt => {
                const lhs = try expectInt(proc.regs[instr.b]);
                const rhs = try expectInt(proc.regs[instr.c]);
                const is_true = lhs > rhs;
                proc.cond_code = @intCast(@as(u8, @intFromBool(is_true)));
                proc.regs[instr.a] = Value{ .int = if (is_true) 1 else 0 };
                proc.ip += 1;
            },
            .lteq => {
                const lhs = try expectInt(proc.regs[instr.b]);
                const rhs = try expectInt(proc.regs[instr.c]);
                const is_true = lhs <= rhs;
                proc.cond_code = @intCast(@as(u8, @intFromBool(is_true)));
                proc.regs[instr.a] = Value{ .int = if (is_true) 1 else 0 };
                proc.ip += 1;
            },
            .gteq => {
                const lhs = try expectInt(proc.regs[instr.b]);
                const rhs = try expectInt(proc.regs[instr.c]);
                const is_true = lhs >= rhs;
                proc.cond_code = @intCast(@as(u8, @intFromBool(is_true)));
                proc.regs[instr.a] = Value{ .int = if (is_true) 1 else 0 };
                proc.ip += 1;
            },
            .jmp_true => {
                if (proc.cond_code == 1) {
                    proc.ip = instr.a;
                } else {
                    proc.ip += 1;
                }
            },
            .jmp_not => {
                if (proc.cond_code == 0) {
                    proc.ip = instr.a;
                } else {
                    proc.ip += 1;
                }
            },
            .recv => {
                // block until we get a message
                if (proc.mailbox.items.len == 0) {
                    proc.status = .waiting;
                    return;
                }

                const msg = proc.mailbox.orderedRemove(0);
                proc.regs[instr.a] = msg.payload;
                if (instr.b != instr.a) {
                    proc.regs[instr.b] = Value{ .pid = msg.sender };
                }
                proc.ip += 1;
            },
            .jmp => {
                proc.ip = instr.a;
            },
            .call => {
                const target_ip = instr.a;
                const arg_start = @as(usize, instr.b);
                const arg_count = @as(usize, instr.c);
                if (arg_start + arg_count > proc.reg_count) return error.InvalidCallArgs;

                const caller_base = proc.reg_base;
                const caller_reg_count = proc.reg_count;

                const frame = Frame{
                    .reg_base = caller_base,
                    .reg_count = caller_reg_count,
                    .cond_code = proc.cond_code,
                    .return_ip = proc.ip + 1,
                    .return_dest = instr.b,
                };
                try proc.frames.append(vm.allocator, frame);

                const new_reg_count = @max(proc.program.registerCountFor(target_ip), @as(usize, 1));
                const new_base = proc.reg_base + proc.reg_count;
                const needed_len = new_base + new_reg_count;
                if (needed_len > proc.reg_stack.items.len) {
                    try proc.reg_stack.resize(vm.allocator, needed_len);
                }
                const caller_regs = proc.reg_stack.items[caller_base .. caller_base + caller_reg_count];
                const new_regs = proc.reg_stack.items[new_base..needed_len];
                for (new_regs) |*r| r.* = Value{ .unit = {} };

                var i: usize = 0;
                while (i < arg_count) : (i += 1) {
                    if (i >= new_reg_count) return error.InvalidCallArgs;
                    new_regs[i] = caller_regs[arg_start + i];
                }

                proc.regs = new_regs;
                proc.reg_base = new_base;
                proc.reg_count = new_reg_count;
                proc.cond_code = 0;
                proc.ip = target_ip;
            },
            .ret => {
                const ret_val = proc.regs[instr.a];
                if (proc.frames.items.len == 0) {
                    proc.status = .dead;
                    return;
                }

                const frame = proc.frames.pop() orelse unreachable;
                const shrink_len = frame.reg_base + frame.reg_count;
                if (proc.reg_stack.items.len > shrink_len) {
                    proc.reg_stack.shrinkRetainingCapacity(shrink_len);
                }
                proc.reg_base = frame.reg_base;
                proc.reg_count = frame.reg_count;
                proc.regs = proc.reg_stack.items[frame.reg_base..shrink_len];
                proc.cond_code = frame.cond_code;
                proc.ip = frame.return_ip;
                proc.regs[frame.return_dest] = ret_val;
            },
            .self => {
                proc.regs[instr.a] = Value{ .pid = proc.id };
                proc.ip += 1;
            },
            .halt => {
                proc.status = .dead;
            },
            .print => {
                var stdout_buffer: [256]u8 = undefined;
                var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
                const stdout = &stdout_writer.interface;
                try Value.print(proc.regs[instr.a], &vm.heap, proc.program.atoms, stdout);
                try stdout.print("\n", .{});
                try stdout.flush();
                proc.ip += 1;
            },
            .atom => {
                const atom_id: u16 = (@as(u16, instr.b) << 8) | instr.c;
                proc.regs[instr.a] = Value{ .atom = atom_id };
                proc.ip += 1;
            },
        }
    }

    // sendMessage sends a given value into the mailbox of another process.
    fn sendMessage(vm: *VM, from_pid: usize, to_pid: usize, msg: Value) !void {
        if (to_pid >= vm.processes.items.len) return error.NoSuchPid;
        const maybe_proc = &vm.processes.items[to_pid];
        if (maybe_proc.* == null) return error.NoSuchPid;

        if (maybe_proc.*) |*proc| {
            try proc.mailbox.append(vm.allocator, Message{
                .sender = from_pid,
                .payload = msg,
            });

            // if it was blocked on RECV, wake it up
            if (proc.status == .waiting) {
                proc.status = .ready;
                try vm.run_queue.append(vm.allocator, to_pid);
            }
        }
    }

    fn markValue(vm: *VM, value: Value) void {
        switch (value) {
            .string => |handle| vm.heap.mark(handle),
            else => {},
        }
    }

    /// collect runs a simple mark & sweep over all string values visible to the VM.
    pub fn collect(vm: *VM) void {
        vm.heap.clearMarks();

        for (vm.processes.items) |maybe_proc| {
            if (maybe_proc) |proc| {
                for (proc.regs) |v| markValue(vm, v);
                for (proc.frames.items) |frame| {
                    const frame_end = frame.reg_base + frame.reg_count;
                    if (frame_end <= proc.reg_stack.items.len) {
                        for (proc.reg_stack.items[frame.reg_base..frame_end]) |v| {
                            markValue(vm, v);
                        }
                    }
                }
                for (proc.mailbox.items) |msg| {
                    markValue(vm, msg.payload);
                }
            }
        }

        vm.heap.sweep();
    }

    pub fn liveStrings(vm: *VM) usize {
        var count: usize = 0;
        for (vm.heap.entries.items) |entry| {
            if (entry.in_use) count += 1;
        }
        return count;
    }

    pub fn allocString(vm: *VM, bytes: []const u8) !Value {
        const handle = try vm.heap.allocString(bytes);
        return Value{ .string = handle };
    }

    /// readRegister returns the value stored in a register for a given process id.
    pub fn readRegister(vm: *VM, pid: usize, reg: usize) !Value {
        if (pid >= vm.processes.items.len) return error.NoSuchPid;
        const proc = vm.processes.items[pid] orelse return error.NoSuchPid;
        if (reg >= proc.reg_count) return error.InvalidRegister;
        return proc.regs[reg];
    }
};

fn expectInt(v: Value) !i64 {
    return switch (v) {
        .int => |val| val,
        else => error.TypeMismatch,
    };
}

fn expectPid(v: Value) !usize {
    return switch (v) {
        .pid => |pid| pid,
        else => error.TypeMismatch,
    };
}

test "arithmetic instructions execute" {
    const gpa = std.testing.allocator;
    var vm = try VM.init(gpa);
    defer vm.deinit();

    const code = [_]Instr{
        .{ .op = .add, .a = 2, .b = 0, .c = 1 },
        .{ .op = .sub, .a = 3, .b = 2, .c = 1 },
        .{ .op = .halt, .a = 0, .b = 0, .c = 0 },
    };

    debugInstructions(&code);

    const program = Program{ .code = &code, .strings = &[_][]const u8{} };
    const pid = try vm.spawn(program, 0);
    var proc = &vm.processes.items[pid].?;
    proc.regs[0] = Value{ .int = 2 };
    proc.regs[1] = Value{ .int = 3 };

    try vm.run();

    const final = vm.processes.items[pid].?;
    try std.testing.expect(final.status == .dead);
    try std.testing.expectEqual(@as(i64, 5), try expectInt(final.regs[2]));
    try std.testing.expectEqual(@as(i64, 2), try expectInt(final.regs[3]));
}

test "condition instructions drive jumps" {
    const gpa = std.testing.allocator;
    var vm = try VM.init(gpa);
    defer vm.deinit();

    const code = [_]Instr{
        .{ .op = .lt, .a = 5, .b = 0, .c = 1 }, // 1 < 2 -> true
        .{ .op = .jmp_true, .a = 3, .b = 0, .c = 0 }, // skip imm at 2
        .{ .op = .imm, .a = 2, .b = 99, .c = 0 }, // should be skipped
        .{ .op = .gt, .a = 6, .b = 0, .c = 1 }, // 1 > 2 -> false
        .{ .op = .jmp_not, .a = 6, .b = 0, .c = 0 }, // skip imm at 5
        .{ .op = .imm, .a = 3, .b = 99, .c = 0 }, // should be skipped
        .{ .op = .gteq, .a = 7, .b = 1, .c = 0 }, // 2 >= 1 -> true
        .{ .op = .jmp_true, .a = 9, .b = 0, .c = 0 }, // skip imm at 8
        .{ .op = .imm, .a = 4, .b = 99, .c = 0 }, // should be skipped
        .{ .op = .lteq, .a = 8, .b = 0, .c = 0 }, // 1 <= 1 -> true
        .{ .op = .halt, .a = 0, .b = 0, .c = 0 },
    };

    const program = Program{ .code = &code, .strings = &[_][]const u8{} };
    const pid = try vm.spawn(program, 0);
    var proc = &vm.processes.items[pid].?;
    proc.regs[0] = Value{ .int = 1 };
    proc.regs[1] = Value{ .int = 2 };
    proc.regs[2] = Value{ .int = 0 };
    proc.regs[3] = Value{ .int = 0 };
    proc.regs[4] = Value{ .int = 0 };

    try vm.run();

    const final = vm.processes.items[pid].?;
    try std.testing.expectEqual(@as(ProcessStatus, .dead), final.status);
    try std.testing.expectEqual(@as(i64, 1), try expectInt(final.regs[0]));
    try std.testing.expectEqual(@as(i64, 2), try expectInt(final.regs[1]));
    try std.testing.expectEqual(@as(i64, 0), try expectInt(final.regs[2]));
    try std.testing.expectEqual(@as(i64, 0), try expectInt(final.regs[3]));
    try std.testing.expectEqual(@as(i64, 0), try expectInt(final.regs[4]));
    try std.testing.expectEqual(@as(u8, 1), final.cond_code);
}

test "call executes function and returns" {
    const gpa = std.testing.allocator;
    var vm = try VM.init(gpa);
    defer vm.deinit();

    const code = [_]Instr{
        .{ .op = .call, .a = 2, .b = 4, .c = 2 }, // dest r4, args r4-r5
        .{ .op = .halt, .a = 0, .b = 0, .c = 0 },
        .{ .op = .add, .a = 0, .b = 0, .c = 1 }, // fn body: r0 = r0 + r1
        .{ .op = .ret, .a = 0, .b = 0, .c = 0 },
    };

    const program = Program{ .code = &code, .strings = &[_][]const u8{} };
    const pid = try vm.spawn(program, 0);
    var proc = &vm.processes.items[pid].?;
    proc.regs[0] = Value{ .int = 9 }; // ensure caller regs survive
    proc.regs[4] = Value{ .int = 2 };
    proc.regs[5] = Value{ .int = 3 };

    try vm.run();

    const final = vm.processes.items[pid].?;
    try std.testing.expectEqual(@as(ProcessStatus, .dead), final.status);
    try std.testing.expectEqual(@as(i64, 5), try expectInt(final.regs[4]));
    try std.testing.expectEqual(@as(i64, 9), try expectInt(final.regs[0]));
    try std.testing.expectEqual(@as(i64, 3), try expectInt(final.regs[5]));
    try std.testing.expectEqual(@as(usize, 0), final.frames.items.len);
}

test "call copies parameters into arg registers" {
    const gpa = std.testing.allocator;
    var vm = try VM.init(gpa);
    defer vm.deinit();

    const code = [_]Instr{
        .{ .op = .call, .a = 3, .b = 1, .c = 2 }, // pass regs1-2 as params
        .{ .op = .halt, .a = 0, .b = 0, .c = 0 },
        .{ .op = .nop, .a = 0, .b = 0, .c = 0 }, // padding
        .{ .op = .sub, .a = 3, .b = 0, .c = 1 }, // r3 = r0 - r1 (11-4)
        .{ .op = .ret, .a = 3, .b = 0, .c = 0 },
    };

    const program = Program{ .code = &code, .strings = &[_][]const u8{} };
    const pid = try vm.spawn(program, 0);
    var proc = &vm.processes.items[pid].?;
    proc.regs[0] = Value{ .int = 100 }; // should remain unchanged
    proc.regs[1] = Value{ .int = 11 };
    proc.regs[2] = Value{ .int = 4 };

    try vm.run();

    const final = vm.processes.items[pid].?;
    try std.testing.expectEqual(@as(ProcessStatus, .dead), final.status);
    try std.testing.expectEqual(@as(i64, 7), try expectInt(final.regs[1]));
    try std.testing.expectEqual(@as(i64, 100), try expectInt(final.regs[0]));
    try std.testing.expectEqual(@as(i64, 4), try expectInt(final.regs[2]));
}

test "nested calls unwind in order" {
    const gpa = std.testing.allocator;
    var vm = try VM.init(gpa);
    defer vm.deinit();

    const code = [_]Instr{
        .{ .op = .imm, .a = 4, .b = 7, .c = 0 }, // load argument for outer
        .{ .op = .call, .a = 3, .b = 4, .c = 1 }, // main -> outer(dest r4)
        .{ .op = .halt, .a = 0, .b = 0, .c = 0 },
        .{ .op = .call, .a = 6, .b = 1, .c = 0 }, // outer -> inner(dest r1)
        .{ .op = .add, .a = 2, .b = 0, .c = 1 }, // r2 = arg0 + inner_ret
        .{ .op = .ret, .a = 2, .b = 0, .c = 0 }, // return sum
        .{ .op = .imm, .a = 0, .b = 10, .c = 0 }, // inner returns 10
        .{ .op = .ret, .a = 0, .b = 0, .c = 0 },
    };

    const program = Program{ .code = &code, .strings = &[_][]const u8{} };
    const pid = try vm.spawn(program, 0);
    var proc = &vm.processes.items[pid].?;
    proc.regs[0] = Value{ .int = 1 }; // ensure preserved
    proc.regs[1] = Value{ .int = 2 };

    try vm.run();

    const final = vm.processes.items[pid].?;
    try std.testing.expectEqual(@as(ProcessStatus, .dead), final.status);
    try std.testing.expectEqual(@as(i64, 17), try expectInt(final.regs[4]));
    try std.testing.expectEqual(@as(i64, 1), try expectInt(final.regs[0]));
    try std.testing.expectEqual(@as(i64, 2), try expectInt(final.regs[1]));
    try std.testing.expectEqual(@as(usize, 0), final.frames.items.len);
}

test "spawn reuses program and returns child pid" {
    const gpa = std.testing.allocator;
    var vm = try VM.init(gpa);
    defer vm.deinit();

    const code = [_]Instr{
        .{ .op = .spawn, .a = 0, .b = 2, .c = 0 },
        .{ .op = .halt, .a = 0, .b = 0, .c = 0 },
        .{ .op = .halt, .a = 0, .b = 0, .c = 0 },
    };

    const program = Program{ .code = &code, .strings = &[_][]const u8{} };
    const parent_pid = try vm.spawn(program, 0);
    try vm.run();

    const parent = vm.processes.items[parent_pid].?;
    const child_pid = try expectPid(parent.regs[0]);
    try std.testing.expectEqual(@as(ProcessStatus, .dead), parent.status);
    try std.testing.expect(child_pid < vm.processes.items.len);
    try std.testing.expect(vm.processes.items[child_pid].?.status == .dead);
}

test "send wakes waiting receiver" {
    const gpa = std.testing.allocator;
    var vm = try VM.init(gpa);
    defer vm.deinit();

    const recv_code = [_]Instr{
        .{ .op = .recv, .a = 0, .b = 0, .c = 0 },
        .{ .op = .halt, .a = 0, .b = 0, .c = 0 },
    };
    const send_code = [_]Instr{
        .{ .op = .send, .a = 0, .b = 1, .c = 0 },
        .{ .op = .halt, .a = 0, .b = 0, .c = 0 },
    };

    const recv_program = Program{ .code = &recv_code, .strings = &[_][]const u8{} };
    const send_program = Program{ .code = &send_code, .strings = &[_][]const u8{} };
    const recv_pid = try vm.spawn(recv_program, 0);
    const send_pid = try vm.spawn(send_program, 0);

    var sender = &vm.processes.items[send_pid].?;
    sender.regs[0] = Value{ .pid = recv_pid };
    sender.regs[1] = Value{ .int = 9 };

    try vm.run();

    const receiver = vm.processes.items[recv_pid].?;
    try std.testing.expectEqual(@as(ProcessStatus, .dead), receiver.status);
    try std.testing.expectEqual(@as(i64, 9), try expectInt(receiver.regs[0]));
    try std.testing.expectEqual(@as(ProcessStatus, .dead), vm.processes.items[send_pid].?.status);
}

test "recv captures sender when requested" {
    const gpa = std.testing.allocator;
    var vm = try VM.init(gpa);
    defer vm.deinit();

    const recv_code = [_]Instr{
        .{ .op = .recv, .a = 0, .b = 1, .c = 0 },
        .{ .op = .halt, .a = 0, .b = 0, .c = 0 },
    };
    const send_code = [_]Instr{
        .{ .op = .send, .a = 0, .b = 1, .c = 0 },
        .{ .op = .halt, .a = 0, .b = 0, .c = 0 },
    };

    const recv_program = Program{ .code = &recv_code, .strings = &[_][]const u8{} };
    const send_program = Program{ .code = &send_code, .strings = &[_][]const u8{} };
    const recv_pid = try vm.spawn(recv_program, 0);
    const send_pid = try vm.spawn(send_program, 0);

    var sender = &vm.processes.items[send_pid].?;
    sender.regs[0] = Value{ .pid = recv_pid };
    sender.regs[1] = Value{ .int = 42 };

    try vm.run();

    const receiver = vm.processes.items[recv_pid].?;
    try std.testing.expectEqual(@as(i64, 42), try expectInt(receiver.regs[0]));
    try std.testing.expectEqual(send_pid, try expectPid(receiver.regs[1]));
}

test "atom instruction produces atom values" {
    const gpa = std.testing.allocator;
    var vm = try VM.init(gpa);
    defer vm.deinit();

    const code = [_]Instr{
        .{ .op = .atom, .a = 0, .b = 0, .c = 1 }, // :world id 1
        .{ .op = .atom, .a = 1, .b = 0, .c = 1 },
        .{ .op = .eq, .a = 0, .b = 1, .c = 0 },
        .{ .op = .halt, .a = 0, .b = 0, .c = 0 },
    };

    const program = Program{
        .code = &code,
        .strings = &[_][]const u8{},
        .atoms = &[_][]const u8{ "hello", "world" },
    };

    const pid = try vm.spawn(program, 0);
    try vm.run();

    const proc = vm.processes.items[pid].?;
    try std.testing.expectEqual(Value{ .atom = 1 }, proc.regs[0]);
    try std.testing.expectEqual(Value{ .atom = 1 }, proc.regs[1]);
    try std.testing.expectEqual(@as(u8, 1), proc.cond_code);
}

test "Value.print renders atoms" {
    var buf = try std.ArrayList(u8).initCapacity(std.testing.allocator, 0);
    defer buf.deinit(std.testing.allocator);

    const atoms = &[_][]const u8{ "foo", "bar" };

    {
        buf.clearRetainingCapacity();
        const writer = buf.writer(std.testing.allocator);
        try Value.print(Value{ .atom = 1 }, null, atoms, writer);
        try std.testing.expectEqualStrings(":bar", buf.items);
    }

    {
        buf.clearRetainingCapacity();
        const writer = buf.writer(std.testing.allocator);
        try Value.print(Value{ .atom = 3 }, null, atoms, writer);
        try std.testing.expectEqualStrings(":3", buf.items);
    }
}

test "self writes current pid" {
    const gpa = std.testing.allocator;
    var vm = try VM.init(gpa);
    defer vm.deinit();

    const code = [_]Instr{
        .{ .op = .self, .a = 3, .b = 0, .c = 0 },
        .{ .op = .halt, .a = 0, .b = 0, .c = 0 },
    };

    const program = Program{ .code = &code, .strings = &[_][]const u8{} };
    const pid = try vm.spawn(program, 0);
    try vm.run();

    const proc = vm.processes.items[pid].?;
    try std.testing.expectEqual(pid, try expectPid(proc.regs[3]));
}

test "strings allocate and are collected when unreachable" {
    const gpa = std.testing.allocator;
    var vm = try VM.init(gpa);
    defer vm.deinit();

    const program = Program{
        .code = &[_]Instr{
            .{ .op = .str, .a = 0, .b = 0, .c = 0 },
            .{ .op = .halt, .a = 0, .b = 0, .c = 0 },
        },
        .strings = &[_][]const u8{"hello"},
    };

    const pid = try vm.spawn(program, 0);
    try vm.run();

    const val = try vm.readRegister(pid, 0);
    var handle: HeapHandle = 0;
    switch (val) {
        .string => |h| handle = h,
        else => try std.testing.expect(false),
    }

    try std.testing.expect(vm.heap.get(handle) != null);
    try std.testing.expectEqual(@as(usize, 1), vm.liveStrings());

    if (vm.processes.items[pid]) |*proc| {
        proc.regs[0] = Value{ .unit = {} };
    }

    vm.collect();
    try std.testing.expectEqual(@as(usize, 0), vm.liveStrings());
    try std.testing.expect(vm.heap.get(handle) == null);
}

test "strings in mailboxes survive collection" {
    const gpa = std.testing.allocator;
    var vm = try VM.init(gpa);
    defer vm.deinit();

    const program = Program{
        .code = &[_]Instr{.{ .op = .halt, .a = 0, .b = 0, .c = 0 }},
        .strings = &[_][]const u8{},
    };

    const pid = try vm.spawn(program, 0);
    const msg = try vm.allocString("queued");
    // clear register so mailbox is sole root
    if (vm.processes.items[pid]) |*proc| {
        proc.regs[0] = Value{ .unit = {} };
    }

    try vm.sendMessage(0, pid, msg);
    try std.testing.expectEqual(@as(usize, 1), vm.liveStrings());

    vm.collect();
    try std.testing.expectEqual(@as(usize, 1), vm.liveStrings()); // mailbox kept it

    // dequeue and drop message, then collect again
    if (vm.processes.items[pid]) |*proc| {
        _ = proc.mailbox.orderedRemove(0);
    }
    vm.collect();
    try std.testing.expectEqual(@as(usize, 0), vm.liveStrings());
}
