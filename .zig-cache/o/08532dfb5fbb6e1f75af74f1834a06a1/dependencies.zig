pub const packages = struct {
    pub const @"zcrypto-0.8.3-rgQAI8wFDAD5qBCumYyC-gCZpzacQHbApwyvXj-ZCbiG" = struct {
        pub const build_root = "/home/chris/.cache/zig/p/zcrypto-0.8.3-rgQAI8wFDAD5qBCumYyC-gCZpzacQHbApwyvXj-ZCbiG";
        pub const build_zig = @import("zcrypto-0.8.3-rgQAI8wFDAD5qBCumYyC-gCZpzacQHbApwyvXj-ZCbiG");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
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
};
