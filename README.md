# RipeMD160

```zig
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

```
