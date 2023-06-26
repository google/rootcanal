// Copyright 2023 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::ffi;
use crate::llcp::iso;
use crate::packets::{hci, llcp};
use std::collections::HashMap;
use std::convert::TryFrom;
use thiserror::Error;

struct Link {
    acl_connection_handle: u16,
    role: hci::Role,
}

pub struct LinkLayer {
    ops: ffi::ControllerOps,
    links: HashMap<u16, Link>,
    iso: iso::IsoManager,
}

#[derive(Error, Debug)]
pub enum LinkLayerError {
    #[error("Unknown peer")]
    UnknownPeer,
    #[error("Link already exists")]
    LinkAlreadyExists,
    #[error("Unhandled HCI packet")]
    UnhandledHciPacket,
    #[error("Invalid HCI packet")]
    InvalidHciPacket,
    #[error("Invalid LLCP packet")]
    InvalidLlcpPacket,
}

impl LinkLayer {
    pub fn new(ops: ffi::ControllerOps) -> LinkLayer {
        let iso = iso::IsoManager::new(ops.clone());
        LinkLayer { ops, links: HashMap::new(), iso }
    }

    pub fn add_link(
        &mut self,
        acl_connection_handle: u16,
        _peer_address: hci::Address,
        role: hci::Role,
    ) -> Result<(), LinkLayerError> {
        if self.links.contains_key(&acl_connection_handle) {
            return Err(LinkLayerError::LinkAlreadyExists);
        }

        self.links.insert(acl_connection_handle, Link { acl_connection_handle, role });
        self.iso.add_acl_connection(acl_connection_handle, role);
        Ok(())
    }

    pub fn remove_link(&mut self, acl_connection_handle: u16) -> Result<(), LinkLayerError> {
        if self.links.remove(&acl_connection_handle).is_none() {
            return Err(LinkLayerError::UnknownPeer);
        }

        self.iso.remove_acl_connection(acl_connection_handle);
        Ok(())
    }

    pub fn tick(&mut self) {}

    pub fn ingest_hci(&mut self, packet: hci::Command) -> Result<(), LinkLayerError> {
        use hci::CommandChild::*;
        match packet.specialize() {
            Disconnect(packet) => self.iso.hci_disconnect(packet),
            LeSetCigParameters(packet) => self.iso.hci_le_set_cig_parameters(packet),
            LeSetCigParametersTest(packet) => self.iso.hci_le_set_cig_parameters_test(packet),
            LeCreateCis(packet) => self.iso.hci_le_create_cis(packet),
            LeRemoveCig(packet) => self.iso.hci_le_remove_cig(packet),
            LeAcceptCisRequest(packet) => self.iso.hci_le_accept_cis_request(packet),
            LeRejectCisRequest(packet) => self.iso.hci_le_reject_cis_request(packet),
            LeSetupIsoDataPath(packet) => self.iso.hci_le_setup_iso_data_path(packet),
            LeRemoveIsoDataPath(packet) => self.iso.hci_le_remove_iso_data_path(packet),
            _ => Err(LinkLayerError::UnhandledHciPacket)?,
        };
        Ok(())
    }

    pub fn ingest_llcp(
        &mut self,
        acl_connection_handle: u16,
        packet: llcp::LlcpPacket,
    ) -> Result<(), LinkLayerError> {
        use llcp::LlcpPacketChild::*;
        match packet.specialize() {
            RejectExtInd(packet) => match llcp::Opcode::try_from(packet.get_reject_opcode()) {
                Ok(llcp::Opcode::LlCisReq) => {
                    self.iso.ll_reject_ext_ind(acl_connection_handle, packet)
                }
                _ => unreachable!(),
            },
            CisReq(packet) => self.iso.ll_cis_req(acl_connection_handle, packet),
            CisRsp(packet) => self.iso.ll_cis_rsp(acl_connection_handle, packet),
            CisInd(packet) => self.iso.ll_cis_ind(acl_connection_handle, packet),
            CisTerminateInd(packet) => self.iso.ll_cis_terminate_ind(acl_connection_handle, packet),
            _ => unimplemented!(),
        }
        Ok(())
    }

    pub fn get_cis_connection_handle(&self, cig_id: u8, cis_id: u8) -> Option<u16> {
        self.iso.get_cis_connection_handle(|cis| cis.cig_id == cig_id && cis.cis_id == cis_id)
    }

    pub fn get_cis(&self, cis_connection_handle: u16) -> Option<&iso::Cis> {
        self.iso.get_cis(cis_connection_handle)
    }
}
