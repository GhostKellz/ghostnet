pub const packages = struct {
    pub const @"zcrypto-0.8.3-rgQAI8wFDAD5qBCumYyC-gCZpzacQHbApwyvXj-ZCbiG" = struct {
        pub const build_root = "/home/chris/.cache/zig/p/zcrypto-0.8.3-rgQAI8wFDAD5qBCumYyC-gCZpzacQHbApwyvXj-ZCbiG";
        pub const build_zig = @import("zcrypto-0.8.3-rgQAI8wFDAD5qBCumYyC-gCZpzacQHbApwyvXj-ZCbiG");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
            .{ "zsync", "zsync-0.3.2-KAuhed0XGADaOKjYNl34Ragvca2zBYqvoAsBV-AhkoLS" },
        };
    };
    pub const @"zquic-0.8.0-2rPdsz6KmRN6DaxicN_GS-x9Gaeg3qlFo6cKfa3s1KDO" = struct {
        pub const build_root = "/home/chris/.cache/zig/p/zquic-0.8.0-2rPdsz6KmRN6DaxicN_GS-x9Gaeg3qlFo6cKfa3s1KDO";
        pub const build_zig = @import("zquic-0.8.0-2rPdsz6KmRN6DaxicN_GS-x9Gaeg3qlFo6cKfa3s1KDO");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
            .{ "zcrypto", "zcrypto-0.8.3-rgQAI8wFDAD5qBCumYyC-gCZpzacQHbApwyvXj-ZCbiG" },
            .{ "zsync", "zsync-0.3.2-KAuhed0XGADaOKjYNl34Ragvca2zBYqvoAsBV-AhkoLS" },
        };
    };
    pub const @"zsync-0.3.2-KAuhed0XGADaOKjYNl34Ragvca2zBYqvoAsBV-AhkoLS" = struct {
        pub const build_root = "/home/chris/.cache/zig/p/zsync-0.3.2-KAuhed0XGADaOKjYNl34Ragvca2zBYqvoAsBV-AhkoLS";
        pub const build_zig = @import("zsync-0.3.2-KAuhed0XGADaOKjYNl34Ragvca2zBYqvoAsBV-AhkoLS");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
        };
    };
};

pub const root_deps: []const struct { []const u8, []const u8 } = &.{
    .{ "zsync", "zsync-0.3.2-KAuhed0XGADaOKjYNl34Ragvca2zBYqvoAsBV-AhkoLS" },
    .{ "zcrypto", "zcrypto-0.8.3-rgQAI8wFDAD5qBCumYyC-gCZpzacQHbApwyvXj-ZCbiG" },
    .{ "zquic", "zquic-0.8.0-2rPdsz6KmRN6DaxicN_GS-x9Gaeg3qlFo6cKfa3s1KDO" },
};
