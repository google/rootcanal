# Copyright 2023 Google Inc. All Rights Reserved.

workspace(name = "com_github_google_rootcanal")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")

new_local_repository(
    name = "fmtlib",
    path = "third_party/fmtlib",
    build_file = "third_party/BUILD.fmtlib",
)

git_repository(
    name = "boringssl",
    # branch master-with-bazel
    commit = "4280d451e661db0c4d800f2c5219f3f4701c7cd0",
    remote = "https://boringssl.googlesource.com/boringssl",
)

local_repository(
    name = "gflags",
    path = "third_party/gflags",
)

new_local_repository(
    name = "pdl",
    path = "third_party/pdl",
    build_file = "third_party/BUILD.pdl",
)

http_archive(
    name = "rules_cc",
    urls = ["https://github.com/bazelbuild/rules_cc/releases/download/0.0.6/rules_cc-0.0.6.tar.gz"],
    sha256 = "3d9e271e2876ba42e114c9b9bc51454e379cbf0ec9ef9d40e2ae4cec61a31b40",
    strip_prefix = "rules_cc-0.0.6",
)

http_archive(
    name = "rules_rust",
    sha256 = "190b5aeba104210f8ed9b1ff595d1f459297fe32db70f0a04f5c537a13ee0602",
    urls = ["https://github.com/bazelbuild/rules_rust/releases/download/0.24.1/rules_rust-v0.24.1.tar.gz"],
)

http_archive(
    name = "rules_proto",
    sha256 = "dc3fb206a2cb3441b485eb1e423165b231235a1ea9b031b4433cf7bc1fa460dd",
    strip_prefix = "rules_proto-5.3.0-21.7",
    urls = [
        "https://github.com/bazelbuild/rules_proto/archive/refs/tags/5.3.0-21.7.tar.gz",
    ],
)

http_archive(
    name = "rules_python",
    sha256 = "84aec9e21cc56fbc7f1335035a71c850d1b9b5cc6ff497306f84cced9a769841",
    strip_prefix = "rules_python-0.23.1",
    url = "https://github.com/bazelbuild/rules_python/releases/download/0.23.1/rules_python-0.23.1.tar.gz",
)

http_archive(
    name = "bazel_skylib",
    sha256 = "66ffd9315665bfaafc96b52278f57c7e2dd09f5ede279ea6d39b2be471e7e3aa",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/1.4.2/bazel-skylib-1.4.2.tar.gz",
        "https://github.com/bazelbuild/bazel-skylib/releases/download/1.4.2/bazel-skylib-1.4.2.tar.gz",
    ],
)

load("@rules_proto//proto:repositories.bzl", "rules_proto_dependencies", "rules_proto_toolchains")
rules_proto_dependencies()
rules_proto_toolchains()

load("@rules_rust//rust:repositories.bzl", "rust_repositories")
rust_repositories(edition="2018")

load("//rust/cargo:crates.bzl", "raze_fetch_remote_crates")
raze_fetch_remote_crates()

load("@rules_python//python:repositories.bzl", "py_repositories")
py_repositories()

load("@bazel_skylib//:workspace.bzl", "bazel_skylib_workspace")
bazel_skylib_workspace()
