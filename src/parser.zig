const std = @import("std");

const LexerError = error{
    UnrecognizedChar,
};

pub const ParserError = error{
    InvalidTokenStmt,
    InvalidExpression,
    ExpectedToken,
    PrecendenceError,
};

pub const ParseError = ParserError || std.mem.Allocator.Error;

pub const TokenTag = enum {
    identifier,
    number,
    keyword_let,
    keyword_spawn,
    keyword_loop,
    keyword_def,
    keyword_if,
    keyword_ret,
    keyword_else,
    l_brace,
    r_brace,
    l_paren,
    r_paren,
    lt,
    gt,
    comma,
    colon,
    semicolon,
    dot,
    equal,
    asterisk,
    plus,
    minus,
    slash,
    eof,

    fn precedence(self: TokenTag) !usize {
        return switch (self) {
            .asterisk => 50,
            .slash => 50,
            .plus => 45,
            .minus => 45,
            .gt => 35,
            .lt => 35,
            .equal => 1,
            else => ParserError.PrecendenceError,
        };
    }
};

pub const Token = struct {
    tag: TokenTag,
    lexeme: []const u8,
    line: usize,
    column: usize,
};

const keywords = std.StaticStringMap(TokenTag).initComptime(.{
    .{ "let", TokenTag.keyword_let },
    .{ "def", TokenTag.keyword_def },
    .{ "spawn", TokenTag.keyword_spawn },
    .{ "loop", TokenTag.keyword_loop },
    .{ "ret", TokenTag.keyword_ret },
    .{ "if", TokenTag.keyword_if },
    .{ "else", TokenTag.keyword_else },
});

pub fn lex(alloc: std.mem.Allocator, source: []const u8) ![]Token {
    var tokens = try std.ArrayList(Token).initCapacity(alloc, 8);
    defer tokens.deinit(alloc);

    var line: usize = 1;
    var col: usize = 1;
    var loc: usize = 0;
    while (loc < source.len) {
        if (std.ascii.isAlphabetic(source[loc])) {
            const start = loc;
            loc += 1;

            while (loc < source.len and std.ascii.isAlphabetic(source[loc])) {
                loc += 1;
            }

            var content = source[start..loc];
            var tag: TokenTag = .identifier;
            if (keywords.get(content)) |ktag| {
                tag = ktag;
                content = ""; // no need to store the lexeme
            }

            try tokens.append(alloc, Token{
                .column = col,
                .line = line,
                .tag = tag,
                .lexeme = content,
            });
            col += loc - start;
            continue;
        }

        if (std.ascii.isDigit(source[loc])) {
            const start = loc;
            loc += 1;
            // TODO: support floating point
            while (loc < source.len and std.ascii.isDigit(source[loc])) {
                loc += 1;
            }

            try tokens.append(alloc, Token{
                .column = col,
                .line = line,
                .tag = .number,
                .lexeme = source[start..loc],
            });
            col += loc - start;
            continue;
        }

        var tag: TokenTag = .eof;
        switch (source[loc]) {
            '\n' => {
                line += 1;
                col = 1;
            },
            '#' => {
                // this is a comment skip until the end
                const sl = source[loc..];
                const end = std.mem.indexOfScalar(u8, sl, '\n') orelse sl.len;
                loc += end;
                line += 1;
                col = 1;

                continue;
            },
            ' ', '\t' => {
                col += 1;
            },
            '{' => {
                tag = .l_brace;
                col += 1;
            },
            '}' => {
                tag = .r_brace;
                col += 1;
            },
            '(' => {
                tag = .l_paren;
                col += 1;
            },
            ')' => {
                tag = .r_paren;
                col += 1;
            },
            ',' => {
                tag = .comma;
                col += 1;
            },
            ':' => {
                tag = .colon;
                col += 1;
            },
            ';' => {
                tag = .semicolon;
                col += 1;
            },
            '.' => {
                tag = .dot;
                col += 1;
            },
            '=' => {
                tag = .equal;
                col += 1;
            },
            '-' => {
                tag = .minus;
                col += 1;
            },
            '*' => {
                tag = .asterisk;
                col += 1;
            },
            '/' => {
                tag = .slash;
                col += 1;
            },
            '+' => {
                tag = .plus;
                col += 1;
            },
            '>' => {
                tag = .gt;
                col += 1;
            },
            '<' => {
                tag = .lt;
                col += 1;
            },
            else => {
                return LexerError.UnrecognizedChar;
            },
        }

        if (tag != .eof) {
            try tokens.append(alloc, Token{
                .column = col,
                .line = line,
                .lexeme = "",
                .tag = tag,
            });
        }

        loc += 1;
    }

    try tokens.append(alloc, Token{
        .column = col,
        .line = line,
        .lexeme = "",
        .tag = .eof,
    });

    return tokens.toOwnedSlice(alloc);
}

pub const StatementTag = enum {
    expression,
    block,
    fn_def,
    var_def,
    ret,
    if_stmt,
};

pub const ExprTag = enum {
    number,
    identifier,
    binary,
    assign,
    function_call,
};

pub const Expr = union(ExprTag) {
    number: i64,
    identifier: []const u8,
    binary: struct {
        left: *Expr,
        operator: TokenTag,
        right: *Expr,
    },
    assign: struct {
        name: []const u8,
        value: *Expr,
    },
    function_call: struct {
        name: []const u8,
        args: []*Expr,
    },

    pub fn deinit(self: *Expr, alloc: std.mem.Allocator) void {
        switch (self.*) {
            .binary => {
                self.binary.left.deinit(alloc);
                self.binary.right.deinit(alloc);
            },
            .assign => {
                self.assign.value.deinit(alloc);
            },
            .function_call => {
                for (self.function_call.args) |arg| {
                    arg.deinit(alloc);
                }
                alloc.free(self.function_call.args);
            },
            else => {},
        }
        alloc.destroy(self);
    }
};

const Param = struct {
    name: []const u8,
};

pub const Statement = union(StatementTag) {
    expression: struct {
        expr: *Expr,
    },
    block: struct {
        stmts: []*Statement,
    },
    fn_def: struct {
        name: []const u8,
        body: *Statement,
        params: []Param,
    },
    var_def: struct {
        name: []const u8,
        value: ?*Expr,
    },
    ret: struct {
        value: ?*Expr,
    },
    if_stmt: struct {
        expr: *Expr,
        then_branch: *Statement,
        else_branch: ?*Statement,
    },

    pub fn deinit(self: *Statement, alloc: std.mem.Allocator) void {
        switch (self.*) {
            .expression => {
                self.expression.expr.deinit(alloc);
            },
            .block => {
                for (self.block.stmts) |stmt| {
                    stmt.deinit(alloc);
                }
                alloc.free(self.block.stmts);
            },
            .fn_def => {
                self.fn_def.body.deinit(alloc);
                alloc.free(self.fn_def.params);
            },
            .var_def => {
                if (self.var_def.value) |val| {
                    val.deinit(alloc);
                }
            },
            .ret => {
                if (self.ret.value) |val| {
                    val.deinit(alloc);
                }
            },
            .if_stmt => {
                self.if_stmt.expr.deinit(alloc);
                self.if_stmt.then_branch.deinit(alloc);

                if (self.if_stmt.else_branch) |eb| {
                    eb.deinit(alloc);
                }
            },
        }
        alloc.destroy(self);
    }
};

pub const Parser = struct {
    tokens: []const Token,
    index: usize,
    alloc: std.mem.Allocator,

    pub fn init(alloc: std.mem.Allocator, tokens: []const Token) !Parser {
        return Parser{
            .alloc = alloc,
            .tokens = tokens,
            .index = 0,
        };
    }

    pub fn deinit(self: *Parser) void {
        _ = self; // parser currently borrows tokens; caller frees them
    }

    fn parseExpression(self: *Parser, min_pred: usize) ParseError!*Expr {
        var left = try self.parseFactor();

        while (self.index < self.tokens.len) {
            const tok = self.peek();
            const pred = tok.tag.precedence() catch break;
            if (pred < min_pred) break;

            switch (tok.tag) {
                .equal => {
                    _ = self.advance();
                    const right = try self.parseExpression(pred);
                    const name = switch (left.*) {
                        .identifier => |id| id,
                        else => return ParseError.InvalidExpression,
                    };
                    left.deinit(self.alloc);

                    const assign_expr = try self.alloc.create(Expr);
                    assign_expr.* = .{
                        .assign = .{
                            .name = name,
                            .value = right,
                        },
                    };
                    left = assign_expr;
                },
                else => {
                    _ = self.advance();
                    const right = try self.parseExpression(pred + 1);
                    const expr = try self.alloc.create(Expr);
                    expr.* = .{
                        .binary = .{
                            .left = left,
                            .operator = tok.tag,
                            .right = right,
                        },
                    };
                    left = expr;
                },
            }
        }

        return left;
    }

    fn parseFactor(self: *Parser) ParseError!*Expr {
        const tok = self.peek();
        switch (tok.tag) {
            .number => {
                _ = self.advance();
                const value = std.fmt.parseInt(i64, tok.lexeme, 10) catch 0;
                const expr = try self.alloc.create(Expr);
                expr.* = .{
                    .number = value,
                };
                return expr;
            },
            .identifier => {
                _ = self.advance();
                if (self.peek().tag == .l_paren) {
                    _ = self.advance(); // consume '('
                    var args = try std.ArrayList(*Expr).initCapacity(self.alloc, 0);
                    defer args.deinit(self.alloc);

                    while (self.peek().tag != .r_paren) {
                        const arg = try self.parseExpression(0);
                        try args.append(self.alloc, arg);

                        if (self.peek().tag == .comma) {
                            _ = self.advance();
                        } else {
                            break;
                        }
                    }

                    try self.expect(.r_paren);

                    const expr = try self.alloc.create(Expr);
                    expr.* = .{
                        .function_call = .{
                            .name = tok.lexeme,
                            .args = try args.toOwnedSlice(self.alloc),
                        },
                    };
                    return expr;
                } else {
                    const expr = try self.alloc.create(Expr);
                    expr.* = .{
                        .identifier = tok.lexeme,
                    };
                    return expr;
                }
            },
            .l_paren => {
                _ = self.advance(); // consume '('
                const inner = try self.parseExpression(0);
                try self.expect(.r_paren);
                return inner;
            },
            else => {
                return ParseError.InvalidTokenStmt;
            },
        }
    }

    fn parseIf(self: *Parser) ParseError!*Statement {
        try self.expect(.keyword_if);
        try self.expect(.l_paren);

        const cond = try self.parseExpression(0);
        errdefer cond.deinit(self.alloc);

        try self.expect(.r_paren);

        const then_branch = try self.parseStatement();
        errdefer then_branch.deinit(self.alloc);

        const stmt = try self.alloc.create(Statement);
        errdefer stmt.deinit(self.alloc);

        stmt.* = .{ .if_stmt = .{
            .expr = cond,
            .then_branch = then_branch,
            .else_branch = null,
        } };

        if (self.match(.keyword_else)) {
            const else_branch = try self.parseStatement();
            errdefer else_branch.deinit(self.alloc);

            stmt.*.if_stmt.else_branch = else_branch;
        }

        return stmt;
    }

    fn parseStatement(self: *Parser) ParseError!*Statement {
        switch (self.peek().tag) {
            .keyword_def => {
                _ = self.advance();
                return try self.parseDef();
            },
            .keyword_if => {
                return try self.parseIf();
            },
            .l_brace => {
                return try self.parseBlock();
            },
            .keyword_ret => {
                _ = self.advance(); // skip ret
                var value: ?*Expr = null;
                if (self.peek().tag != .semicolon) { // if next token is not semicolon parse expr
                    value = try self.parseExpression(0);
                }

                try self.expect(.semicolon); // there must be a semicolon after the return
                const stmt = try self.alloc.create(Statement);
                stmt.* = .{
                    .ret = .{
                        .value = value,
                    },
                };
                return stmt;
            },
            else => {
                const expr = try self.parseExpression(0);
                try self.expect(.semicolon);
                const stmt = try self.alloc.create(Statement);
                stmt.* = .{
                    .expression = .{
                        .expr = expr,
                    },
                };
                return stmt;
            },
        }
    }

    fn parseBlock(self: *Parser) !*Statement {
        try self.expect(.l_brace);
        var statements = try std.ArrayList(*Statement).initCapacity(self.alloc, 0);
        defer statements.deinit(self.alloc);

        while (self.peek().tag != .r_brace) {
            const stmt = try self.parseStatement();
            try statements.append(self.alloc, stmt);
        }

        try self.expect(.r_brace);

        const stmt = try self.alloc.create(Statement);
        stmt.* = .{
            .block = .{
                .stmts = try statements.toOwnedSlice(self.alloc),
            },
        };
        return stmt;
    }

    fn parseDef(self: *Parser) ParseError!*Statement {
        try self.ensure(.identifier);

        const tok = self.advance();
        try self.expect(.l_paren);
        var params = try std.ArrayList(Param).initCapacity(self.alloc, 0);
        defer params.deinit(self.alloc);

        while (self.peek().tag != .r_paren) {
            const param_tok = self.advance();
            if (param_tok.tag != .identifier) {
                return ParseError.InvalidTokenStmt;
            }
            try params.append(self.alloc, Param{
                .name = param_tok.lexeme,
            });

            if (self.peek().tag == .comma) {
                _ = self.advance();
            } else {
                break;
            }
        }
        try self.expect(.r_paren);

        const body = try self.parseBlock();
        const stmt = try self.alloc.create(Statement);
        stmt.* = .{
            .fn_def = .{
                .name = tok.lexeme,
                .params = try params.toOwnedSlice(self.alloc),
                .body = body,
            },
        };
        return stmt;
    }

    pub fn parse(self: *Parser) ![]*Statement {
        var statements = try std.ArrayList(*Statement).initCapacity(self.alloc, 0);
        defer statements.deinit(self.alloc);

        while (self.peek().tag != .eof) {
            const stmt = try self.parseStatement();
            try statements.append(self.alloc, stmt);
        }

        return statements.toOwnedSlice(self.alloc);
    }

    fn peek(self: *Parser) *const Token {
        return &self.tokens[self.index];
    }

    fn advance(self: *Parser) *const Token {
        const tok = &self.tokens[self.index];
        if (self.index + 1 < self.tokens.len) self.index += 1;
        return tok;
    }

    fn match(self: *Parser, tag: TokenTag) bool {
        if (self.peek().tag == tag) {
            _ = self.advance();
            return true;
        }
        return false;
    }

    fn expect(self: *Parser, tag: TokenTag) !void {
        if (!self.match(tag)) return ParseError.ExpectedToken;
    }

    fn ensure(self: *Parser, tag: TokenTag) !void {
        if (self.peek().tag != tag) return ParseError.ExpectedToken;
    }
};

const testing = std.testing;
test "lex numbers" {
    const content = "123 7432 1";
    const tokens = try lex(std.testing.allocator, content);
    defer testing.allocator.free(tokens);

    try testing.expect(tokens.len == 4);
}

test "identifiers and keywords" {
    const content = "def loop hello spawn";
    const tokens = try lex(std.testing.allocator, content);
    defer testing.allocator.free(tokens);

    try testing.expect(tokens.len == 5);

    try testing.expect(std.mem.eql(u8, tokens[0].lexeme, ""));
    try testing.expect(tokens[0].column == @as(usize, 1));
    try testing.expect(tokens[0].line == @as(usize, 1));
    try testing.expect(tokens[0].tag == .keyword_def);

    try testing.expect(std.mem.eql(u8, tokens[1].lexeme, ""));
    try testing.expect(tokens[1].column == @as(usize, 5));
    try testing.expect(tokens[1].line == @as(usize, 1));
    try testing.expect(tokens[1].tag == .keyword_loop);

    try testing.expect(std.mem.eql(u8, tokens[2].lexeme, "hello"));
    try testing.expect(tokens[2].column == @as(usize, 10));
    try testing.expect(tokens[2].line == @as(usize, 1));
    try testing.expect(tokens[2].tag == .identifier);

    try testing.expect(std.mem.eql(u8, tokens[3].lexeme, ""));
    try testing.expect(tokens[3].column == @as(usize, 16));
    try testing.expect(tokens[3].line == @as(usize, 1));
    try testing.expect(tokens[3].tag == .keyword_spawn);
}

test "symbols" {
    const content = "{ } ( ) , : ; . =";
    const tokens = try lex(std.testing.allocator, content);
    defer testing.allocator.free(tokens);

    try testing.expect(tokens.len == 10);

    try testing.expect(tokens[0].tag == .l_brace);
    try testing.expect(tokens[1].tag == .r_brace);
    try testing.expect(tokens[2].tag == .l_paren);
    try testing.expect(tokens[3].tag == .r_paren);
    try testing.expect(tokens[4].tag == .comma);
    try testing.expect(tokens[5].tag == .colon);
    try testing.expect(tokens[6].tag == .semicolon);
    try testing.expect(tokens[7].tag == .dot);
    try testing.expect(tokens[8].tag == .equal);
}

test "simple expression parsing" {
    const content = "a = 5 + 3 * 2;";
    const tokens = try lex(std.testing.allocator, content);
    defer testing.allocator.free(tokens);

    var parser = try Parser.init(std.testing.allocator, tokens);
    defer parser.deinit();

    const stmts = try parser.parse();
    defer {
        for (stmts) |stmt| {
            stmt.deinit(std.testing.allocator);
        }
        std.testing.allocator.free(stmts);
    }

    try testing.expect(stmts.len == 1);
    const stmt = stmts[0];
    try testing.expect(stmt.* == .expression);

    const expr = stmt.expression.expr;

    const assign = expr.assign;
    try testing.expect(std.mem.eql(u8, assign.name, "a"));

    const value_expr = assign.value;
    try testing.expect(value_expr.* == .binary);

    const binary = value_expr.binary;
    try testing.expect(binary.operator == .plus);

    const right_expr = binary.right;
    try testing.expect(right_expr.* == .binary);

    const right_binary = right_expr.binary;
    try testing.expect(right_binary.operator == .asterisk);
}

test "function definition parsing" {
    const content = "def add(a, b) { ret a + b; }";
    const tokens = try lex(std.testing.allocator, content);
    defer testing.allocator.free(tokens);

    var parser = try Parser.init(std.testing.allocator, tokens);
    defer parser.deinit();

    const stmts = try parser.parse();
    defer {
        for (stmts) |stmt| {
            stmt.deinit(std.testing.allocator);
        }
        std.testing.allocator.free(stmts);
    }

    try testing.expect(stmts.len == 1);
    const stmt = stmts[0];
    try testing.expect(stmt.* == .fn_def);

    const fn_def = stmt.fn_def;
    try testing.expect(std.mem.eql(u8, fn_def.name, "add"));
    try testing.expect(fn_def.params.len == 2);
    try testing.expect(std.mem.eql(u8, fn_def.params[0].name, "a"));
    try testing.expect(std.mem.eql(u8, fn_def.params[1].name, "b"));

    const body = fn_def.body;
    try testing.expect(body.* == .block);

    const body_block = body.block;
    try testing.expect(body_block.stmts.len == 1);

    const ret_stmt = body_block.stmts[0];
    try testing.expect(ret_stmt.* == .ret);

    try testing.expect(ret_stmt.ret.value != null);
    const ret_value = ret_stmt.ret.value.?;
    try testing.expect(ret_value.* == .binary);

    const bin_expr = ret_value.binary;
    try testing.expect(bin_expr.operator == .plus);

    const left_expr = bin_expr.left;
    try testing.expect(left_expr.* == .identifier);
    try testing.expect(std.mem.eql(u8, left_expr.identifier, "a"));

    const right_expr = bin_expr.right;
    try testing.expect(right_expr.* == .identifier);
    try testing.expect(std.mem.eql(u8, right_expr.identifier, "b"));
}

test "function call expression parsing" {
    const content = "result = add(1, two);";
    const tokens = try lex(std.testing.allocator, content);
    defer testing.allocator.free(tokens);

    var parser = try Parser.init(std.testing.allocator, tokens);
    defer parser.deinit();

    const stmts = try parser.parse();
    defer {
        for (stmts) |stmt| {
            stmt.deinit(std.testing.allocator);
        }
        std.testing.allocator.free(stmts);
    }

    try testing.expectEqual(@as(usize, 1), stmts.len);
    const expr_stmt = stmts[0];
    try testing.expect(expr_stmt.* == .expression);

    const assign_expr = expr_stmt.expression.expr;
    try testing.expect(assign_expr.* == .assign);
    try testing.expect(std.mem.eql(u8, assign_expr.assign.name, "result"));

    const call_expr = assign_expr.assign.value;
    try testing.expect(call_expr.* == .function_call);
    try testing.expect(std.mem.eql(u8, call_expr.function_call.name, "add"));
    try testing.expectEqual(@as(usize, 2), call_expr.function_call.args.len);

    try testing.expect(call_expr.function_call.args[0].*.number == 1);
    try testing.expect(std.mem.eql(u8, call_expr.function_call.args[1].identifier, "two"));
}

test "if statement parsing correct" {
    const content = "if (x > 0) { ret x; } else { ret 0; }";
    const tokens = try lex(std.testing.allocator, content);
    defer testing.allocator.free(tokens);

    var parser = try Parser.init(std.testing.allocator, tokens);
    defer parser.deinit();

    const stmts = try parser.parse();
    defer {
        for (stmts) |stmt| {
            stmt.deinit(std.testing.allocator);
        }
        std.testing.allocator.free(stmts);
    }

    try testing.expectEqual(@as(usize, 1), stmts.len);
    const if_stmt = stmts[0];
    try testing.expect(if_stmt.* == .if_stmt);

    const if_data = if_stmt.if_stmt;
    const cond_expr = if_data.expr;
    try testing.expect(cond_expr.* == .binary);
    try testing.expect(cond_expr.binary.operator == .gt);

    const then_branch = if_data.then_branch;
    try testing.expect(then_branch.* == .block);
    try testing.expectEqual(@as(usize, 1), then_branch.block.stmts.len);

    const then_ret = then_branch.block.stmts[0];
    try testing.expect(then_ret.* == .ret);
    try testing.expect(then_ret.ret.value != null);

    const then_ret_value = then_ret.ret.value.?;
    try testing.expect(then_ret_value.* == .identifier);
    try testing.expect(std.mem.eql(u8, then_ret_value.identifier, "x"));
    try testing.expect(if_data.else_branch != null);

    const else_branch = if_data.else_branch.?;
    try testing.expect(else_branch.* == .block);
    try testing.expectEqual(@as(usize, 1), else_branch.block.stmts.len);

    const else_ret = else_branch.block.stmts[0];
    try testing.expect(else_ret.* == .ret);
    try testing.expect(else_ret.ret.value != null);

    const else_ret_value = else_ret.ret.value.?;
    try testing.expect(else_ret_value.* == .number);
    try testing.expect(else_ret_value.number == 0);
}

test "lex comments" {
    const content = "# this is a comment\n1";
    const tokens = try lex(std.testing.allocator, content);
    defer testing.allocator.free(tokens);

    try testing.expect(tokens.len == 2);
    try testing.expect(tokens[0].tag == .number);
    try testing.expect(std.mem.eql(u8, tokens[0].lexeme, "1"));
    try testing.expect(tokens[1].tag == .eof);
}
