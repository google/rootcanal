# Copyright 2023 Google Inc. All Rights Reserved.

load("@rules_cc//cc:defs.bzl", "cc_binary")
load("@rules_cc//cc:defs.bzl", "cc_library")
load("@rules_proto//proto:defs.bzl", "proto_library")
load("@rules_rust//rust:defs.bzl", "rust_static_library")

package(default_visibility = ["//visibility:private"])
licenses(["notice"])

exports_files(["LICENSE"])

cc_library(
    name = "rootcanal_log",
    srcs = ["lib/log.cc"],
    hdrs = ["include/log.h"],
    includes = ["include"],
    copts = ["-std=c++17"],
    deps = [
        "@fmtlib",
    ],
)

proto_library(
    name = "rootcanal_proto",
    srcs = ["proto/rootcanal/configuration.proto"],
    strip_import_prefix = "proto",
)

cc_proto_library(
    name = "rootcanal_config",
    deps = [":rootcanal_proto"],
)

genrule(
    name = "lmp_packets_rs",
    cmd = "pdlc --output-format rust_legacy $(location rust/lmp_packets.pdl) > $(location lmp_packets.rs)",
    outs = ["lmp_packets.rs"],
    srcs = ["rust/lmp_packets.pdl"],
)

genrule(
    name = "llcp_packets_rs",
    cmd = "pdlc --output-format rust_legacy $(location rust/llcp_packets.pdl) > $(location llcp_packets.rs)",
    outs = ["llcp_packets.rs"],
    srcs = ["rust/llcp_packets.pdl"],
)

genrule(
    name = "hci_packets_rs",
    cmd = "pdlc --output-format rust_legacy $(location //packets:hci_packets.pdl) > $(location hci_packets.rs)",
    outs = ["hci_packets.rs"],
    srcs = ["//packets:hci_packets.pdl"],
    visibility = ["//visibility:public"],
)

rust_static_library(
    name = "rootcanal_rs",
    edition = "2018",
    crate_root = "rust/src/lib.rs",
    rustc_env = {
        "HCI_PACKETS_PREBUILT": "$(location hci_packets.rs)",
        "LMP_PACKETS_PREBUILT": "$(location lmp_packets.rs)",
        "LLCP_PACKETS_PREBUILT": "$(location llcp_packets.rs)",
    },
    srcs = [
        "rust/src/either.rs",
        "rust/src/ffi.rs",
        "rust/src/future.rs",
        "rust/src/lib.rs",
        "rust/src/llcp/iso.rs",
        "rust/src/llcp/manager.rs",
        "rust/src/llcp/mod.rs",
        "rust/src/lmp/ec.rs",
        "rust/src/lmp/manager.rs",
        "rust/src/lmp/mod.rs",
        "rust/src/lmp/procedure/authentication.rs",
        "rust/src/lmp/procedure/encryption.rs",
        "rust/src/lmp/procedure/features.rs",
        "rust/src/lmp/procedure/legacy_pairing.rs",
        "rust/src/lmp/procedure/mod.rs",
        "rust/src/lmp/procedure/secure_simple_pairing.rs",
        "rust/src/packets.rs",
    ],
    compile_data = [
        "hci_packets.rs",
        "llcp_packets.rs",
        "lmp_packets.rs",
    ],
    proc_macro_deps = [
        "@crates//:num-derive",
        "@crates//:paste",
    ],
    deps = [
        "@crates//:bytes",
        "@crates//:num-bigint",
        "@crates//:num-integer",
        "@crates//:num-traits",
        "@crates//:pdl-runtime",
        "@crates//:pin-utils",
        "@crates//:rand",
        "@crates//:thiserror",
    ],
)

cc_binary(
    name = "librootcanal_ffi.so",
    linkopts = ["-shared"],
    srcs = [
        "include/crypto/crypto.h",
        "include/hci/address.h",
        "include/hci/address_with_type.h",
        "include/hci/pcap_filter.h",
        "include/log.h",
        "include/pcap.h",
        "include/phy.h",
        "lib/crypto/crypto.cc",
        "lib/hci/address.cc",
        "model/controller/acl_connection.cc",
        "model/controller/acl_connection.h",
        "model/controller/acl_connection_handler.cc",
        "model/controller/acl_connection_handler.h",
        "model/controller/controller_properties.cc",
        "model/controller/controller_properties.h",
        "model/controller/dual_mode_controller.cc",
        "model/controller/dual_mode_controller.h",
        "model/controller/le_advertiser.cc",
        "model/controller/le_advertiser.h",
        "model/controller/link_layer_controller.cc",
        "model/controller/link_layer_controller.h",
        "model/controller/sco_connection.cc",
        "model/controller/sco_connection.h",
        "model/controller/vendor_commands/csr.h",
        "model/controller/vendor_commands/le_apcf.cc",
        "model/controller/vendor_commands/le_apcf.h",
        "model/controller/ffi.cc",
        "model/controller/ffi.h",
        "model/devices/device.cc",
        "model/devices/device.h",
        "rust/include/rootcanal_rs.h",
    ],
    copts = [
        "-std=c++17",
        "-Wno-c99-designator",
        "-Wno-google3-literal-operator",
        "-Wno-pessimizing-move",
        "-include",
        "string.h",
        "-I.",
        "-fmacro-prefix-map=external/rootcanal/=",
    ],
    defines = [
        "NDEBUG",
        "_GNU_SOURCE",
    ],
    includes = [
        "include",
        "rust/include",
    ],
    visibility = ["//visibility:public"],
    deps = [
        ":rootcanal_config",
        ":rootcanal_log",
        ":rootcanal_rs",
        "//packets:generated",
        "@pdl//:packet_runtime",
        "@fmtlib",
        "@openssl//:crypto",
    ],
)

cc_binary(
    name = "rootcanal",
    srcs = [
        "desktop/root_canal_main.cc",
        "desktop/test_environment.cc",
        "desktop/test_environment.h",
        "include/crypto/crypto.h",
        "include/hci/address.h",
        "include/hci/address_with_type.h",
        "include/hci/pcap_filter.h",
        "include/log.h",
        "include/pcap.h",
        "include/phy.h",
        "lib/crypto/crypto.cc",
        "lib/hci/address.cc",
        "lib/hci/pcap_filter.cc",
        "model/controller/acl_connection.cc",
        "model/controller/acl_connection.h",
        "model/controller/acl_connection_handler.cc",
        "model/controller/acl_connection_handler.h",
        "model/controller/controller_properties.cc",
        "model/controller/controller_properties.h",
        "model/controller/dual_mode_controller.cc",
        "model/controller/dual_mode_controller.h",
        "model/controller/le_advertiser.cc",
        "model/controller/le_advertiser.h",
        "model/controller/link_layer_controller.cc",
        "model/controller/link_layer_controller.h",
        "model/controller/sco_connection.cc",
        "model/controller/sco_connection.h",
        "model/controller/vendor_commands/csr.h",
        "model/controller/vendor_commands/le_apcf.cc",
        "model/controller/vendor_commands/le_apcf.h",
        "model/devices/baseband_sniffer.cc",
        "model/devices/baseband_sniffer.h",
        "model/devices/beacon.cc",
        "model/devices/beacon.h",
        "model/devices/device.cc",
        "model/devices/device.h",
        "model/devices/hci_device.cc",
        "model/devices/hci_device.h",
        "model/devices/link_layer_socket_device.cc",
        "model/devices/link_layer_socket_device.h",
        "model/devices/sniffer.cc",
        "model/devices/sniffer.h",
        "model/hci/h4.h",
        "model/hci/h4_data_channel_packetizer.cc",
        "model/hci/h4_data_channel_packetizer.h",
        "model/hci/h4_parser.cc",
        "model/hci/h4_parser.h",
        "model/hci/hci_sniffer.cc",
        "model/hci/hci_sniffer.h",
        "model/hci/hci_socket_transport.cc",
        "model/hci/hci_socket_transport.h",
        "model/hci/hci_transport.h",
        "model/setup/async_manager.cc",
        "model/setup/async_manager.h",
        "model/setup/device_boutique.cc",
        "model/setup/device_boutique.h",
        "model/setup/phy_device.cc",
        "model/setup/phy_device.h",
        "model/setup/phy_layer.cc",
        "model/setup/phy_layer.h",
        "model/setup/test_channel_transport.cc",
        "model/setup/test_channel_transport.h",
        "model/setup/test_command_handler.cc",
        "model/setup/test_command_handler.h",
        "model/setup/test_model.cc",
        "model/setup/test_model.h",
        "net/async_data_channel.h",
        "net/async_data_channel_connector.h",
        "net/async_data_channel_server.h",
        "net/posix/posix_async_socket.cc",
        "net/posix/posix_async_socket.h",
        "net/posix/posix_async_socket_connector.cc",
        "net/posix/posix_async_socket_connector.h",
        "net/posix/posix_async_socket_server.cc",
        "net/posix/posix_async_socket_server.h",
        "rust/include/rootcanal_rs.h",
    ],
    copts = [
        "-std=c++17",
        "-Wno-c99-designator",
        "-Wno-google3-literal-operator",
        "-Wno-pessimizing-move",
        "-include",
        "string.h",
        "-I.",
        "-fmacro-prefix-map=external/rootcanal/=",
    ],
    defines = [
        "NDEBUG",
        "_GNU_SOURCE",
    ],
    includes = [
        "include",
        "rust/include",
    ],
    visibility = ["//visibility:public"],
    deps = [
        ":rootcanal_config",
        ":rootcanal_log",
        ":rootcanal_rs",
        "//packets:generated",
        "@gflags",
        "@fmtlib",
        "@openssl//:crypto",
        "@pdl//:packet_runtime",
    ],
    # TODO enable thin_lto
    # breaks the device registration
    # features = ["-thin_lto"],
)

load("@hedron_compile_commands//:refresh_compile_commands.bzl", "refresh_compile_commands")

refresh_compile_commands(
    name = "refresh_compile_commands",

    # Specify the targets of interest.
    # For example, specify a dict of targets and any flags required to build.
    targets = {
      "//:rootcanal": "",
    },
    # No need to add flags already in .bazelrc. They're automatically picked up.
    # If you don't need flags, a list of targets is also okay, as is a single target string.
    # Wildcard patterns, like //... for everything, *are* allowed here, just like a build.
      # As are additional targets (+) and subtractions (-), like in bazel query https://docs.bazel.build/versions/main/query.html#expressions
    # And if you're working on a header-only library, specify a test or binary target that compiles it.
    exclude_external_sources = True,
)
