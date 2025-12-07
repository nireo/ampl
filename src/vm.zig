const std = @import("std");

pub const ValueTag = enum {
    int,
    pid,
    unit,
};

pub const Value = union(ValueTag) {
    int: i64,
    pid: usize,
    unit: void,
};

const Message = struct {
    sender: usize,
    payload: Value,
};

pub const Op = enum(u8) {
    nop,
    mov,
    imm,
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
};

pub const Instr = struct {
    op: Op,
    a: u8,
    b: u8,
    c: u8,

    fn debugPrint(self: Instr) void {
        std.debug.print("\t{} {} {} {}\n", .{ self.op, self.a, self.b, self.c });
    }
};

fn debugInstructions(code: []const Instr) void {
    for (code, 0..) |instr, idx| {
        std.debug.print("{}: ", .{idx});
        instr.debugPrint();
    }
}

/// MAX_REGS describes the amount of registers that a process should have.
const MAX_REGS = 256;

/// Number of instructions a process may execute before it is preempted and
/// returned to the run queue. This is done such that we don't really want to
/// return a process to the run queue after for example executing one add instruction.
const REDUCTIONS_PER_SLICE: usize = 100;

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
/// which the instructions manipulate, this obviously has very basic things such as conditionCode
/// ip, code, call_stack etc which are very common. Additionally processes have a mailbox, which can
/// be used to receive information from other processes.
const Process = struct {
    id: usize,
    regs: [MAX_REGS]Value,
    cond_code: u8,
    ip: usize,
    code: []const Instr,
    mailbox: std.ArrayList(Message),
    call_stack: std.ArrayList(usize),
    status: ProcessStatus,
};

pub const VM = struct {
    allocator: std.mem.Allocator,
    processes: std.ArrayList(?Process),
    run_queue: std.ArrayList(usize),

    /// init sets up a basic vm with some capacity for processes and a run queue.
    pub fn init(alloc: std.mem.Allocator) !VM {
        return VM{
            .allocator = alloc,
            .processes = try std.ArrayList(?Process).initCapacity(alloc, 128),
            .run_queue = try std.ArrayList(usize).initCapacity(alloc, 128),
        };
    }

    /// deinit frees the resources used by the vm
    pub fn deinit(vm: *VM) void {
        // deinit each process
        for (vm.processes.items) |*maybe_proc| {
            if (maybe_proc.*) |*proc| {
                proc.mailbox.deinit(vm.allocator);
                proc.call_stack.deinit(vm.allocator);
            }
        }

        // deinit the arrays themselves.
        vm.processes.deinit(vm.allocator);
        vm.run_queue.deinit(vm.allocator);
    }

    /// spawn sets up a new process with some given code and a staring instruction pointer.
    /// It first tries to look for a processor in the list if every processor is taken it adds
    /// a new one to the list. this function also appends the new process to the run queue.
    pub fn spawn(vm: *VM, code: []const Instr, start_ip: usize) !usize {
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

        // basic process init & run queue append
        const mailbox = std.ArrayList(Message).empty;
        var proc = Process{
            .id = pid,
            .regs = undefined,
            .cond_code = 0,
            .ip = start_ip,
            .code = code,
            .mailbox = mailbox,
            .call_stack = std.ArrayList(usize).empty,
            .status = .ready,
        };

        // zero registers
        for (&proc.regs) |*r| r.* = Value{ .unit = {} };

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
        if (proc.ip >= proc.code.len) {
            proc.status = .dead;
            return;
        }

        const instr = proc.code[proc.ip];
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
                const pid = try vm.spawn(proc.code, child_ip);
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
                const lhs = try expectInt(proc.regs[instr.a]);
                const rhs = try expectInt(proc.regs[instr.b]);

                proc.cond_code = if (lhs < rhs) 1 else 0;
                proc.ip += 1;
            },
            .gt => {
                const lhs = try expectInt(proc.regs[instr.a]);
                const rhs = try expectInt(proc.regs[instr.b]);

                proc.cond_code = if (lhs > rhs) 1 else 0;
                proc.ip += 1;
            },
            .lteq => {
                const lhs = try expectInt(proc.regs[instr.a]);
                const rhs = try expectInt(proc.regs[instr.b]);

                proc.cond_code = if (lhs <= rhs) 1 else 0;
                proc.ip += 1;
            },
            .gteq => {
                const lhs = try expectInt(proc.regs[instr.a]);
                const rhs = try expectInt(proc.regs[instr.b]);

                proc.cond_code = if (lhs >= rhs) 1 else 0;
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
                const arg_start = @as(usize, instr.b);
                const arg_count = @as(usize, instr.c);
                if (arg_start + arg_count > MAX_REGS) return error.InvalidCallArgs;

                // copy arguments into the callee's argument registers starting at r0
                var i: usize = 0;
                while (i < arg_count) : (i += 1) {
                    proc.regs[i] = proc.regs[arg_start + i];
                }

                try proc.call_stack.append(vm.allocator, proc.ip + 1);
                proc.ip = instr.a;
            },
            .ret => {
                if (proc.call_stack.items.len == 0) {
                    proc.status = .dead;
                    return;
                }
                proc.ip = proc.call_stack.pop() orelse unreachable;
            },
            .self => {
                proc.regs[instr.a] = Value{ .pid = proc.id };
                proc.ip += 1;
            },
            .halt => {
                proc.status = .dead;
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

    /// readRegister returns the value stored in a register for a given process id.
    pub fn readRegister(vm: *VM, pid: usize, reg: usize) !Value {
        if (pid >= vm.processes.items.len) return error.NoSuchPid;
        const proc = vm.processes.items[pid] orelse return error.NoSuchPid;
        if (reg >= MAX_REGS) return error.InvalidRegister;
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

    const pid = try vm.spawn(&code, 0);
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
        .{ .op = .lt, .a = 0, .b = 1, .c = 0 }, // 1 < 2 -> true
        .{ .op = .jmp_true, .a = 3, .b = 0, .c = 0 }, // skip imm at 2
        .{ .op = .imm, .a = 2, .b = 99, .c = 0 }, // should be skipped
        .{ .op = .gt, .a = 0, .b = 1, .c = 0 }, // 1 > 2 -> false
        .{ .op = .jmp_not, .a = 6, .b = 0, .c = 0 }, // skip imm at 5
        .{ .op = .imm, .a = 3, .b = 99, .c = 0 }, // should be skipped
        .{ .op = .gteq, .a = 1, .b = 0, .c = 0 }, // 2 >= 1 -> true
        .{ .op = .jmp_true, .a = 9, .b = 0, .c = 0 }, // skip imm at 8
        .{ .op = .imm, .a = 4, .b = 99, .c = 0 }, // should be skipped
        .{ .op = .lteq, .a = 0, .b = 0, .c = 0 }, // 1 <= 1 -> true
        .{ .op = .halt, .a = 0, .b = 0, .c = 0 },
    };

    const pid = try vm.spawn(&code, 0);
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
        .{ .op = .call, .a = 2, .b = 0, .c = 0 }, // jump to fn
        .{ .op = .halt, .a = 0, .b = 0, .c = 0 },
        .{ .op = .add, .a = 0, .b = 0, .c = 1 }, // fn body: r0 = r0 + r1
        .{ .op = .ret, .a = 0, .b = 0, .c = 0 },
    };

    const pid = try vm.spawn(&code, 0);
    var proc = &vm.processes.items[pid].?;
    proc.regs[0] = Value{ .int = 2 };
    proc.regs[1] = Value{ .int = 3 };

    try vm.run();

    const final = vm.processes.items[pid].?;
    try std.testing.expectEqual(@as(ProcessStatus, .dead), final.status);
    try std.testing.expectEqual(@as(i64, 5), try expectInt(final.regs[0]));
    try std.testing.expectEqual(@as(usize, 0), final.call_stack.items.len);
}

test "call copies parameters into arg registers" {
    const gpa = std.testing.allocator;
    var vm = try VM.init(gpa);
    defer vm.deinit();

    const code = [_]Instr{
        .{ .op = .call, .a = 3, .b = 2, .c = 2 }, // pass regs2-3 as params
        .{ .op = .halt, .a = 0, .b = 0, .c = 0 },
        .{ .op = .nop, .a = 0, .b = 0, .c = 0 }, // padding
        .{ .op = .add, .a = 4, .b = 0, .c = 1 }, // r4 = r0 + r1 (7+11)
        .{ .op = .ret, .a = 0, .b = 0, .c = 0 },
    };

    const pid = try vm.spawn(&code, 0);
    var proc = &vm.processes.items[pid].?;
    proc.regs[2] = Value{ .int = 7 };
    proc.regs[3] = Value{ .int = 11 };

    try vm.run();

    const final = vm.processes.items[pid].?;
    try std.testing.expectEqual(@as(ProcessStatus, .dead), final.status);
    try std.testing.expectEqual(@as(i64, 7), try expectInt(final.regs[0]));
    try std.testing.expectEqual(@as(i64, 11), try expectInt(final.regs[1]));
    try std.testing.expectEqual(@as(i64, 18), try expectInt(final.regs[4]));
}

test "nested calls unwind in order" {
    const gpa = std.testing.allocator;
    var vm = try VM.init(gpa);
    defer vm.deinit();

    const code = [_]Instr{
        .{ .op = .call, .a = 2, .b = 0, .c = 0 }, // main -> outer
        .{ .op = .halt, .a = 0, .b = 0, .c = 0 },
        .{ .op = .call, .a = 5, .b = 0, .c = 0 }, // outer -> inner
        .{ .op = .add, .a = 2, .b = 3, .c = 1 }, // r2 = r3 + r1
        .{ .op = .ret, .a = 0, .b = 0, .c = 0 }, // return to main
        .{ .op = .add, .a = 3, .b = 0, .c = 1 }, // inner: r3 = r0 + r1
        .{ .op = .ret, .a = 0, .b = 0, .c = 0 },
    };

    const pid = try vm.spawn(&code, 0);
    var proc = &vm.processes.items[pid].?;
    proc.regs[0] = Value{ .int = 5 };
    proc.regs[1] = Value{ .int = 1 };
    proc.regs[2] = Value{ .int = 0 };
    proc.regs[3] = Value{ .int = 0 };

    try vm.run();

    const final = vm.processes.items[pid].?;
    try std.testing.expectEqual(@as(ProcessStatus, .dead), final.status);
    try std.testing.expectEqual(@as(i64, 6), try expectInt(final.regs[3]));
    try std.testing.expectEqual(@as(i64, 7), try expectInt(final.regs[2]));
    try std.testing.expectEqual(@as(usize, 0), final.call_stack.items.len);
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

    const parent_pid = try vm.spawn(&code, 0);
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

    const recv_pid = try vm.spawn(&recv_code, 0);
    const send_pid = try vm.spawn(&send_code, 0);

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

    const recv_pid = try vm.spawn(&recv_code, 0);
    const send_pid = try vm.spawn(&send_code, 0);

    var sender = &vm.processes.items[send_pid].?;
    sender.regs[0] = Value{ .pid = recv_pid };
    sender.regs[1] = Value{ .int = 42 };

    try vm.run();

    const receiver = vm.processes.items[recv_pid].?;
    try std.testing.expectEqual(@as(i64, 42), try expectInt(receiver.regs[0]));
    try std.testing.expectEqual(send_pid, try expectPid(receiver.regs[1]));
}

test "self writes current pid" {
    const gpa = std.testing.allocator;
    var vm = try VM.init(gpa);
    defer vm.deinit();

    const code = [_]Instr{
        .{ .op = .self, .a = 3, .b = 0, .c = 0 },
        .{ .op = .halt, .a = 0, .b = 0, .c = 0 },
    };

    const pid = try vm.spawn(&code, 0);
    try vm.run();

    const proc = vm.processes.items[pid].?;
    try std.testing.expectEqual(pid, try expectPid(proc.regs[3]));
}
