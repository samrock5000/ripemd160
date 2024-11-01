const std = @import("std");
const assert = std.debug.assert;

//ripemd160 port of https://github.com/paulmillr/noble-hashes/blob/main/src/ripemd160.ts

const Kl = [5]u32{
    0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e,
};
const Kr = [5]u32{
    0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000,
};
const Rho = [_]u8{ 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8 };
const Id = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };

const Pi = blk: {
    var pi: [16]u8 = undefined;
    for (Id, 0..) |i, index| {
        pi[index] = @intCast((9 * i + 5) % 16);
    }
    break :blk pi;
};

const Indices = struct {
    idxL: [5][16]u8,
    idxR: [5][16]u8,
};

fn computeIndices() Indices {
    var idxL: [5][16]u8 = undefined;
    var idxR: [5][16]u8 = undefined;

    // Initialize the first elements of idxL and idxR
    for (Id, 0..) |i, index| {
        idxL[0][index] = i;
        idxR[0][index] = Pi[index];
    }

    for (0..4) |i| {
        for ([_]*[5][16]u8{ &idxL, &idxR }) |j| {
            for (0..16) |k| {
                j[i + 1][k] = Rho[j[i][k]];
            }
        }
    }

    return Indices{ .idxL = idxL, .idxR = idxR };
}

const Shifts = struct {
    shiftsL: [5][16]u8,
    shiftsR: [5][16]u8,
};

fn computeShifts(indices: Indices) Shifts {
    var shiftsL: [5][16]u8 = undefined;
    var shiftsR: [5][16]u8 = undefined;
    const shifts = [_][16]u8{
        [_]u8{ 11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8 },
        [_]u8{ 12, 13, 11, 15, 6, 9, 9, 7, 12, 15, 11, 13, 7, 8, 7, 7 },
        [_]u8{ 13, 15, 14, 11, 7, 7, 6, 8, 13, 14, 13, 12, 5, 5, 6, 9 },
        [_]u8{ 14, 11, 12, 14, 8, 6, 5, 5, 15, 12, 15, 14, 9, 9, 8, 6 },
        [_]u8{ 15, 12, 13, 13, 9, 5, 8, 6, 14, 11, 12, 11, 8, 6, 5, 5 },
    };

    for (0..5) |i| {
        for (0..16) |j| {
            shiftsL[i][j] = shifts[i][indices.idxL[i][j]];
            shiftsR[i][j] = shifts[i][indices.idxR[i][j]];
        }
    }

    return Shifts{ .shiftsL = shiftsL, .shiftsR = shiftsR };
}

pub const Ripemd160 = struct {
    const Self = @This();
    pub const block_length = 64;
    pub const digest_length = 20;
    pub const Options = struct {};
    const indices = computeIndices();
    const shifts = computeShifts(indices);

    _h0: u32,
    _h1: u32,
    _h2: u32,
    _h3: u32,
    _h4: u32,
    // Streaming Cache
    buf: [64]u8,
    buf_len: u8,
    total_len: u64,

    pub fn set(self: *Ripemd160, h0: u32, h1: u32, h2: u32, h3: u32, h4: u32) void {
        self._h0 = h0 | 0;
        self._h1 = h1 | 0;
        self._h2 = h2 | 0;
        self._h3 = h3 | 0;
        self._h4 = h4 | 0;
    }
    pub fn init(options: Options) Self {
        _ = options;
        return Self{
            ._h0 = 0x67452301,
            ._h1 = 0xEFCDAB89,
            ._h2 = 0x98BADCFE,
            ._h3 = 0x10325476,
            ._h4 = 0xC3D2E1F0,
            .buf = undefined,
            .buf_len = 0,
            .total_len = 0,
        };
    }
    pub fn hash(b: []const u8, out: *[digest_length]u8, options: Options) void {
        var d = Ripemd160.init(options);
        d.update(b);
        d.final(out);
    }

    pub fn update(d: *Self, b: []const u8) void {
        var off: usize = 0;

        // Partial buffer exists from previous update. Copy into buffer then hash.
        if (d.buf_len != 0 and d.buf_len + b.len >= 64) {
            off += 64 - d.buf_len;
            @memcpy(d.buf[d.buf_len..][0..off], b[0..off]);

            d.process(&d.buf);
            d.buf_len = 0;
        }

        // Full middle blocks.
        while (off + 64 <= b.len) : (off += 64) {
            d.process(b[off..][0..64]);
        }

        // Copy any remainder for next pass.
        const b_slice = b[off..];
        @memcpy(d.buf[d.buf_len..][0..b_slice.len], b_slice);
        d.buf_len += @as(u8, @intCast(b_slice.len));

        // Md5 uses the bottom 64-bits for length padding
        d.total_len +%= b.len;
    }

    pub fn final(d: *Self, out: *[digest_length]u8) void {
        // The buffer here will never be completely full.
        var off: usize = 0;
        @memset(d.buf[d.buf_len..], 0);

        // Append padding bits.
        d.buf[d.buf_len] = 0x80;
        d.buf_len += 1;

        // > 448 mod 512 so need to add an extra process to wrap aprocess.
        if (64 - d.buf_len < 8) {
            off += 64 - d.buf_len;
            d.process(d.buf[0..]);
            @memset(d.buf[0..], 0);
        }

        // Append message length.
        var i: usize = 1;
        var len = d.total_len >> 5;
        d.buf[56] = @as(u8, @intCast(d.total_len & 0x1f)) << 3;
        while (i < 8) : (i += 1) {
            d.buf[56 + i] = @as(u8, @intCast(len & 0xff));
            len >>= 8;
        }

        d.process(d.buf[0..]);

        std.mem.writeInt(u32, out[4 * 0 ..][0..4], d._h0, .little);
        std.mem.writeInt(u32, out[4 * 1 ..][0..4], d._h1, .little);
        std.mem.writeInt(u32, out[4 * 2 ..][0..4], d._h2, .little);
        std.mem.writeInt(u32, out[4 * 3 ..][0..4], d._h3, .little);
        std.mem.writeInt(u32, out[4 * 4 ..][0..4], d._h4, .little);
    }
    fn f(group: u32, x: u32, y: u32, z: u32) u32 {
        if (group == 0) {
            return x ^ y ^ z;
        } else if (group == 1) {
            return (x & y) | (~x & z);
        } else if (group == 2) {
            return (x | ~y) ^ z;
        } else if (group == 3) {
            return (x & z) | (y & ~z);
        } else return x ^ (y | ~z);
    }
    pub fn process(self: *Self, view: []const u8) void {
        var R_BUF: [16]u32 = undefined;
        var ix: usize = 0;
        while (ix < 16) : (ix += 1) {
            R_BUF[ix] = std.mem.readInt(u32, view[ix * 4 ..][0..4], .little);
        }

        var al = self._h0 | 0;
        var ar = al;
        var bl = self._h1 | 0;
        var br = bl;
        var cl = self._h2 | 0;
        var cr = cl;
        var dl = self._h3 | 0;
        var dr = dl;
        var el = self._h4 | 0;
        var er = el;

        for (0..5) |group| {
            const r_group: u32 = 4 - @as(u32, @intCast(group));
            const hbl = Kl[group];
            const hbr = Kr[group];
            const rl = indices.idxL[group];
            const rr = indices.idxR[group];
            const sl = shifts.shiftsL[group];
            const sr = shifts.shiftsR[group];

            for (0..16) |i| {
                const tl = (std.math.rotl(u32, al +% f(@intCast(group), bl, cl, dl) +% R_BUF[rl[i]] +% hbl, sl[i]) +% el) | 0;
                al = el;
                el = dl;
                dl = std.math.rotl(u32, cl, 10) | 0;
                cl = bl;
                bl = tl;
            }

            for (0..16) |i| {
                const tr = (std.math.rotl(u32, ar +% f(r_group, br, cr, dr) +% R_BUF[rr[i]] +% hbr, sr[i]) +% er) | 0;
                ar = er;
                er = dr;
                dr = std.math.rotl(u32, cr, 10) | 0;
                cr = br;
                br = tr;
            }
        }

        self.set((self._h1 +% cl +% dr) | 0, (self._h2 +% dl +% er) | 0, (self._h3 +% el +% ar) | 0, (self._h4 +% al +% br) | 0, (self._h0 +% bl +% cr) | 0);
    }
};

const nist_test = [_]struct {
    input: []const u8,
    expected: []const u8,
}{
    .{ .input = "abc", .expected = "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc" },
    .{ .input = "", .expected = "9c1185a5c5e9fc54612808977ee8f548b2258d31" },
    .{ .input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", .expected = "12a053384a9c0c88e405a06c27dcf49ada62eb2b" },
    .{ .input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", .expected = "6f3fa39b6b503c384f919a49a7aa5c2c08bdfb45" },
    .{ .input = "a" ** 1000000, .expected = "52783243c1697bdbe16d37f97f68f08325dc1528" },
    .{ .input = "1234567890" ** 8, .expected = "9b752e45573d4b39f4dbd3323cab82bf63326bfb" },
};
test "hash test" {
    var output: [20]u8 = undefined;
    var expect: [20]u8 = undefined;

    for (nist_test) |test_case| {
        _ = try std.fmt.hexToBytes(&expect, test_case.expected);
        Ripemd160.hash(test_case.input, &output, .{});
        const res = std.mem.eql(u8, expect[0..], output[0..]);
        std.debug.assert(res);
    }
}
