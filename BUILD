# Copyright 2023 Google Inc. All Rights Reserved.

load("@rules_cc//cc:defs.bzl", "cc_binary")
load("@rules_cc//cc:defs.bzl", "cc_library")
load("@rules_cc//cc:defs.bzl", "cc_proto_library")
load("@rules_proto//proto:defs.bzl", "proto_library")
load("@rules_rust//rust:defs.bzl", "rust_static_library")
load("@bazel_skylib//rules:run_binary.bzl", "run_binary")

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
    srcs = ["config.proto"],
)

cc_proto_library(
    name = "rootcanal_config",
    deps = [":rootcanal_proto"],
)

genrule(
    name = "lmp_packets_rs",
    cmd = "pdlc --output-format rust $(location rust/lmp_packets.pdl) > $(location lmp_packets.rs)",
    outs = ["lmp_packets.rs"],
    srcs = ["rust/lmp_packets.pdl"],
)

genrule(
    name = "llcp_packets_rs",
    cmd = "pdlc --output-format rust $(location rust/llcp_packets.pdl) > $(location llcp_packets.rs)",
    outs = ["llcp_packets.rs"],
    srcs = ["rust/llcp_packets.pdl"],
)

genrule(
    name = "hci_packets_rs",
    cmd = "pdlc --output-format rust $(location //packets:hci/hci_packets.pdl) > $(location hci_packets.rs)",
    outs = ["hci_packets.rs"],
    srcs = ["//packets:hci/hci_packets.pdl"],
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
        "//rust/cargo:num_derive",
        "//rust/cargo:paste",
    ],
    deps = [
        "//rust/cargo:bytes",
        "//rust/cargo:num_bigint",
        "//rust/cargo:num_integer",
        "//rust/cargo:num_traits",
        "//rust/cargo:pin_utils",
        "//rust/cargo:rand",
        "//rust/cargo:thiserror",
    ],
)

cc_library(
    name = "rootcanal_lib",
    srcs = [
        "desktop/test_environment.cc",
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
        "model/devices/baseband_sniffer.cc",
        "model/devices/baseband_sniffer.h",
        "model/devices/beacon.cc",
        "model/devices/beacon.h",
        "model/devices/beacon_swarm.cc",
        "model/devices/beacon_swarm.h",
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
        "net/posix/posix_async_socket_server.cc",
        "rust/include/rootcanal_rs.h",
    ],
    hdrs = [
        "desktop/test_environment.h",
        "model/setup/async_manager.h",
        "net/posix/posix_async_socket_connector.h",
        "net/posix/posix_async_socket_server.h",
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
        "@fmtlib",
        "@boringssl//:crypto",
        "@pdl//:packet_runtime",
    ],
)

cc_binary(
    name = "rootcanal",
    srcs = ["desktop/root_canal_main.cc"],
    copts = ["-std=c++17"],
    # TODO enable thin_lto
    # breaks the device registration
    # features = ["-thin_lto"],
    visibility = ["//visibility:public"],
    deps = [
        ":rootcanal_lib",
        ":rootcanal_config",
        ":rootcanal_log",
        ":rootcanal_rs",
        "@gflags",
        "@fmtlib",
    ],
)
