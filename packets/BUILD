# Copyright 2023 Google Inc. All Rights Reserved.

load("@bazel_skylib//rules:run_binary.bzl", "run_binary")

package(default_visibility = ["//visibility:public"])
exports_files(["hci_packets.pdl"])

genrule(
    name = "hci_packets_json",
    cmd = "pdlc $(location hci_packets.pdl) > $(location hci_packets.json)",
    outs = ["hci_packets.json"],
    srcs = ["hci_packets.pdl"],
)

genrule(
    name = "bredr_bb_packets_json",
    cmd = "pdlc $(location bredr_bb_packets.pdl) > $(location bredr_bb_packets.json)",
    outs = ["bredr_bb_packets.json"],
    srcs = ["bredr_bb_packets.pdl"],
)

genrule(
    name = "link_layer_packets_json",
    cmd = "pdlc $(location link_layer_packets.pdl) > $(location link_layer_packets.json)",
    outs = ["link_layer_packets.json"],
    srcs = ["link_layer_packets.pdl"],
)

run_binary(
    name = "hci_packets_h",
    args = [
        "--input", "$(location hci_packets.json)",
        "--output", "$(location hci_packets.h)",
        "--namespace", "bluetooth::hci",
        "--include-header", "hci/address.h",
    ],
    outs = ["hci_packets.h"],
    srcs = ["hci_packets.json"],
    tool = "@pdl//:generate_cxx_backend",
)

run_binary(
    name = "bredr_bb_packets_h",
    args = [
        "--input", "$(location bredr_bb_packets.json)",
        "--output", "$(location bredr_bb_packets.h)",
        "--namespace", "bredr_bb",
        "--include-header", "hci/address.h",
        "--using-namespace", "bluetooth::hci",
    ],
    outs = ["bredr_bb_packets.h"],
    srcs = ["bredr_bb_packets.json"],
    tool = "@pdl//:generate_cxx_backend",
)

run_binary(
    name = "link_layer_packets_h",
    args = [
        "--input", "$(location link_layer_packets.json)",
        "--output", "$(location link_layer_packets.h)",
        "--namespace", "model::packets",
        "--include-header", "hci/address.h",
        "--using-namespace", "bluetooth::hci",
    ],
    outs = ["link_layer_packets.h"],
    srcs = ["link_layer_packets.json"],
    tool = "@pdl//:generate_cxx_backend",
)

cc_library(
    name = "generated",
    hdrs = [
        "hci_packets.h",
        "link_layer_packets.h",
        "bredr_bb_packets.h",
    ],
    visibility = ["//visibility:public"],
)
