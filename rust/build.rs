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
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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

fn generate_module(in_file: &PathBuf) {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let out_file =
        File::create(out_dir.join(in_file.file_name().unwrap()).with_extension("rs")).unwrap();

    // Find the pdl tool. Expecting it at CARGO_HOME/bin
    let pdl = match env::var("CARGO_HOME") {
        Ok(dir) => PathBuf::from(dir).join("bin").join("pdlc"),
        Err(_) => PathBuf::from("pdlc"),
    };

    if !Path::new(pdl.as_os_str()).exists() {
        panic!("pdl not found in the current environment: {:?}", pdl.as_os_str().to_str().unwrap());
    }

    println!("cargo:rerun-if-changed={}", in_file.display());
    let output = Command::new(pdl.as_os_str().to_str().unwrap())
        .arg("--output-format")
        .arg("rust")
        .arg(in_file)
        .stdout(Stdio::from(out_file))
        .output()
        .unwrap();

    println!(
        "Status: {}, stderr: {}",
        output.status,
        String::from_utf8_lossy(output.stderr.as_slice())
    );

    assert!(output.status.success());
}
