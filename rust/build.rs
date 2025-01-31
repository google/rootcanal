//  Copyright 2022 Google, Inc.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at:
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

use std::env;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

fn main() {
    install_generated_module(
        "lmp_packets.rs",
        "LMP_PACKETS_PREBUILT",
        &PathBuf::from("lmp_packets.pdl").canonicalize().unwrap(),
    );
    install_generated_module(
        "llcp_packets.rs",
        "LLCP_PACKETS_PREBUILT",
        &PathBuf::from("llcp_packets.pdl").canonicalize().unwrap(),
    );
    install_generated_module(
        "hci_packets.rs",
        "HCI_PACKETS_PREBUILT",
        &PathBuf::from("../packets/hci_packets.pdl").canonicalize().unwrap(),
    );
}

fn install_generated_module(module_name: &str, prebuilt_var: &str, pdl_name: &PathBuf) {
    let module_prebuilt = match env::var(prebuilt_var) {
        Ok(dir) => PathBuf::from(dir),
        Err(_) => PathBuf::from(module_name),
    };

    if Path::new(module_prebuilt.as_os_str()).exists() {
        let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
        std::fs::copy(
            module_prebuilt.as_os_str().to_str().unwrap(),
            out_dir.join(module_name).as_os_str().to_str().unwrap(),
        )
        .unwrap();
    } else {
        generate_module(pdl_name);
    }
}

fn generate_module(in_file: &Path) {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let mut out_file =
        File::create(out_dir.join(in_file.file_name().unwrap()).with_extension("rs")).unwrap();

    println!("cargo:rerun-if-changed={}", in_file.display());

    let mut sources = pdl_compiler::ast::SourceDatabase::new();
    let parsed_file = pdl_compiler::parser::parse_file(
        &mut sources,
        in_file.to_str().expect("Filename is not UTF-8"),
    )
    .expect("PDL parse failed");
    let analyzed_file = pdl_compiler::analyzer::analyze(&parsed_file).expect("PDL analysis failed");
    let rust_source = pdl_compiler::backends::rust_legacy::generate(&sources, &analyzed_file);
    out_file.write_all(rust_source.as_bytes()).expect("Could not write to output file");
}
