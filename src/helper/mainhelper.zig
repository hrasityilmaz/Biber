const std = @import("std");
const elf = @import("elf.zig");
const win = @import("win.zig");
const elfparser = @import("elfparse.zig");
const winparser = @import("winparse.zig");

const e = std.log.err;
const print = std.debug.print;

const Format = enum {
    elf,
    pe,
    unknown,
};

pub const Options = struct {
    file: ?[]const u8 = null,
    all: bool = false,
    headers: bool = false,
    sections: bool = false,
    symbols: bool = false,
    pe_directories: bool = false,
    pe_imports: bool = false,
    pe_exports: bool = false,
    pe_debug: bool = false,
    pe_exceptions: bool = false,
    elf_programs: bool = false,
    elf_dynamic: bool = false,
    elf_relocs: bool = false,
    elf_notes: bool = false,
    dump: bool = false,
    dis: bool = false,
    offset: usize = 0,
    length: usize = 0,
};

const Cmd = enum {
    file,
    all,
    headers,
    sections,
    symbols,
    pe_directories,
    pe_imports,
    pe_exports,
    pe_debug,
    pe_exceptions,
    elf_programs,
    elf_dynamic,
    elf_relocs,
    elf_notes,
    dump,
    dis,
    unknown,
};

fn parseCmd(arg: []const u8) Cmd {
    if (std.mem.eql(u8, arg, "-f")) return .file;
    if (std.mem.eql(u8, arg, "-all")) return .all;
    if (std.mem.eql(u8, arg, "-headers")) return .headers;
    if (std.mem.eql(u8, arg, "-sections")) return .sections;
    if (std.mem.eql(u8, arg, "-symbols")) return .symbols;
    if (std.mem.eql(u8, arg, "-pe-directories")) return .pe_directories;
    if (std.mem.eql(u8, arg, "-pe-imports")) return .pe_imports;
    if (std.mem.eql(u8, arg, "-pe-exports")) return .pe_exports;
    if (std.mem.eql(u8, arg, "-pe-debug")) return .pe_debug;
    if (std.mem.eql(u8, arg, "-pe-exceptions")) return .pe_exceptions;
    if (std.mem.eql(u8, arg, "-elf-programs")) return .elf_programs;
    if (std.mem.eql(u8, arg, "-elf-dynamic")) return .elf_dynamic;
    if (std.mem.eql(u8, arg, "-elf-relocs")) return .elf_relocs;
    if (std.mem.eql(u8, arg, "-elf-notes")) return .elf_notes;
    if (std.mem.eql(u8, arg, "-dump")) return .dump;
    if (std.mem.eql(u8, arg, "-dis")) return .dis;
    return .unknown;
}

pub fn parseNumber(s: []const u8) !usize {
    if (std.mem.startsWith(u8, s, "0x") or std.mem.startsWith(u8, s, "0X")) {
        return try std.fmt.parseInt(usize, s[2..], 16);
    }

    return try std.fmt.parseInt(usize, s, 10);
}

pub fn parseArgs(args: []const [:0]const u8) !Options {
    var opt = Options{};
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const cmd = parseCmd(args[i]);

        switch (cmd) {
            .file => {
                i += 1;
                if (i >= args.len)
                    return error.MissingFile;
                opt.file = args[i];
            },
            .all => {
                opt.all = true;
            },

            .headers => {
                opt.headers = true;
            },
            .sections => {
                opt.sections = true;
            },
            .symbols => {
                opt.symbols = true;
            },
            .pe_directories => {
                opt.pe_directories = true;
            },
            .pe_imports => {
                opt.pe_imports = true;
            },
            .pe_exports => {
                opt.pe_exports = true;
            },
            .pe_debug => {
                opt.pe_debug = true;
            },
            .pe_exceptions => {
                opt.pe_exceptions = true;
            },
            .elf_programs => {
                opt.elf_programs = true;
            },
            .elf_dynamic => {
                opt.elf_dynamic = true;
            },
            .elf_relocs => {
                opt.elf_relocs = true;
            },
            .elf_notes => {
                opt.elf_notes = true;
            },
            .dump => {
                opt.dump = true;
                i += 1;
                if (i >= args.len)
                    return error.MissingOffset;
                opt.offset = try parseNumber(args[i]);
                i += 1;
                if (i >= args.len)
                    return error.MissingLength;
                opt.length = try parseNumber(args[i]);
            },
            .dis => {
                opt.dis = true;
                i += 1;
                if (i >= args.len)
                    return error.MissingOffset;
                opt.offset = try parseNumber(args[i]);
                i += 1;
                if (i >= args.len)
                    return error.MissingLength;
                opt.length = try parseNumber(args[i]);
            },
            .unknown => {
                std.debug.print(
                    "Unknown option: {s}\n",
                    .{args[i]},
                );
                return error.UnknownOption;
            },
        }
    }
    return opt;
}

pub fn detectFormat(data: []const u8) Format {
    if (data.len >= 4 and std.mem.eql(u8, data[0..4], &elf.ELFMAG)) {
        return .elf;
    }
    if (data.len >= 2 and std.mem.readInt(u16, data[0..2], .little) == win.DOS_MAGIC) {
        return .pe;
    }
    return .unknown;
}

pub fn hexDump(data: []const u8, offset: usize, length: usize) void {
    if (offset >= data.len) {
        e("[ERROR] offset outside file", .{});
        return;
    }
    const end = @min(offset + length, data.len);
    const bytes = data[offset..end];
    var i: usize = 0;
    print("\n", .{});
    while (i < bytes.len) : (i += 16) {
        print("{X:0>8}  ", .{offset + i});
        const row_end = @min(i + 16, bytes.len);
        for (bytes[i..row_end]) |b| {
            print("{X:0>2} ", .{b});
        }
        print("\n", .{});
    }
    print("\n", .{});
}

pub fn runElf(data: []const u8, opt: Options) !void {
    if (opt.pe_directories or opt.pe_imports or opt.pe_exports or opt.pe_debug or opt.pe_exceptions) {
        e("[ERROR] PE option used on ELF file", .{});
        return;
    }
    try elfparser.parseElf(data, opt);
}

pub fn runPe(data: []const u8, opt: Options) !void {
    if (opt.elf_programs or opt.elf_dynamic or opt.elf_relocs or opt.elf_notes) {
        e("[ERROR] ELF option used on PE file", .{});
        return;
    }
    try winparser.parsePe(data, opt);
}
