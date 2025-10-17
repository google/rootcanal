# Copyright (C) 2025 Google Inc. All Rights Reserved.

load("@rules_rust//cargo:defs.bzl", "cargo_build_script")
load("@rules_rust//rust:defs.bzl", "rust_static_library")

exports_files(["include/rootcanal_rs.h"])

cargo_build_script(
    name = "rootcanal_rs_build",
    srcs = ["build.rs"],
    deps = [
        "@crates//:pdl-compiler",
    ],
    data = [
        "hci_packets.pdl",
        "llcp_packets.pdl",
        "lmp_packets.pdl",
    ],
)

rust_static_library(
    name = "rootcanal_rs",
    edition = "2018",
    crate_root = "src/lib.rs",
    srcs = [
        "src/either.rs",
        "src/ffi.rs",
        "src/future.rs",
        "src/lib.rs",
        "src/llcp/iso.rs",
        "src/llcp/manager.rs",
        "src/llcp/mod.rs",
        "src/lmp/ec.rs",
        "src/lmp/manager.rs",
        "src/lmp/mod.rs",
        "src/lmp/procedure/authentication.rs",
        "src/lmp/procedure/encryption.rs",
        "src/lmp/procedure/features.rs",
        "src/lmp/procedure/legacy_pairing.rs",
        "src/lmp/procedure/mod.rs",
        "src/lmp/procedure/secure_simple_pairing.rs",
        "src/packets.rs",
    ],
    proc_macro_deps = [
        "@crates//:num-derive",
        "@crates//:paste",
    ],
    deps = [
	":rootcanal_rs_build",
        "@crates//:bytes",
        "@crates//:num-bigint",
        "@crates//:num-integer",
        "@crates//:num-traits",
        "@crates//:pdl-runtime",
        "@crates//:pin-utils",
        "@crates//:rand",
        "@crates//:thiserror",
    ],
    visibility = ["//visibility:public"],
)
