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
use crate::packets::{hci, llcp};
use pdl_runtime::Packet as _;
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};

#[derive(Clone, Copy, Debug)]
enum IsoDataPath {
    Hci,
}

// Description of CIS configuration parameters:
//
// - ISO_Interval (multiple of 1.25ms)
//      ISO_Interval is the time between the CIS anchor points of adjacent CIS
//      events. ISO_Interval is equal for all CISes in a CIG.
// - Sub_Interval (ms)
//      Sub_Interval is the time between start of two consecutive
//      subevents of a CIS
// - NSE
//      NSE is the maximum number of subevents in each CIS event.
// - BN (Burst Number)
//      BN is the number of payloads expected in each CIS event.
//      Each CIS event has NSE - BN retransmission slots.
// - FT (Flush Timeout)
//      The Flush Timeout (FT) parameter is the maximum number of CIS events
//      that may be used to transmit (and retransmit) a given payload
// - Framed
//      Framed indicates whether the CIS carries framed or unframed data; the
//      value shall be the same in both directions.
//      Unframed PDUs shall only be used when the ISO_Interval is equal to
//      or an integer multiple of the SDU_Interval.
//
// For the purpose of emulating the CISes, the intervals between CIS subevents,
// and different CIS events are ignored, leading to a number of approximations:
//
// - CIG_Sync_Delay = ISO_Interval
//      The CIG synchronization point is the same as the next event anchor
// - CIS_Sync_Delay = ISO_Interval
//      All CISes start on the CIG anchor.
// - BN = NSE
//      Unless otherwise specified in test commands.
//      No retransmission slots.
// - FT = 1
//      All PDUs are sent within one event.
// - Sub_Interval = ISO_Interval / NSE

#[allow(non_camel_case_types)]
type microseconds = u32;

#[allow(non_camel_case_types)]
type slots = u16;

/// CIG configuration.
#[derive(Clone, Debug, Default)]
struct CigConfig {
    // CIG parameters.
    iso_interval: slots,
    sdu_interval_c_to_p: microseconds,
    sdu_interval_p_to_c: microseconds,
    ft_c_to_p: u8,
    ft_p_to_c: u8,
    framed: bool,
    // True when the CIG can still be configured.
    configurable: bool,
}

/// CIS configuration.
#[derive(Clone, Debug, Default)]
struct CisConfig {
    // CIS parameters.
    // cf Vol 6, Part B § 4.5.13.1 CIS parameters.
    max_sdu_c_to_p: u16,
    max_sdu_p_to_c: u16,
    phy_c_to_p: u8,
    phy_p_to_c: u8,
    nse: Option<u8>,
    bn_c_to_p: Option<u8>,
    bn_p_to_c: Option<u8>,
    max_pdu_c_to_p: Option<u16>,
    max_pdu_p_to_c: Option<u16>,
}

/// CIG configuration.
#[derive(Clone, Debug, Default)]
struct CisRequest {
    cig_id: u8,
    cis_id: u8,
    acl_connection_handle: u16,
    cis_connection_handle: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CisState {
    Configuration,
    PendingRsp,
    PendingAccept,
    PendingInd,
    Connected,
}

/// Full CIS configuration parameters, evaluated when the CIS is created
/// or established.
#[derive(Clone, Debug)]
struct CisParameters {
    cig_sync_delay: microseconds,
    cis_sync_delay: microseconds,
    phy_c_to_p: u8,
    phy_p_to_c: u8,
    nse: u8,
    bn_c_to_p: u8,
    bn_p_to_c: u8,
    ft_c_to_p: u8,
    ft_p_to_c: u8,
    max_pdu_c_to_p: u16,
    max_pdu_p_to_c: u16,
    max_sdu_c_to_p: u16,
    max_sdu_p_to_c: u16,
    sdu_interval_c_to_p: microseconds,
    sdu_interval_p_to_c: microseconds,
    iso_interval: slots,
    sub_interval: microseconds,
    framed: bool,
}

impl CisParameters {
    fn new(cig_config: &CigConfig, cis_config: &CisConfig) -> CisParameters {
        let bn_c_to_p: u8 = cis_config
            .bn_c_to_p
            .unwrap_or_else(|| ((cis_config.max_sdu_c_to_p + 250) / 251).try_into().unwrap());
        let bn_p_to_c: u8 = cis_config
            .bn_p_to_c
            .unwrap_or_else(|| ((cis_config.max_sdu_p_to_c + 250) / 251).try_into().unwrap());
        let nse = cis_config.nse.unwrap_or(std::cmp::max(bn_c_to_p, bn_p_to_c));
        let max_pdu_c_to_p = cis_config.max_pdu_c_to_p.unwrap_or(251);
        let max_pdu_p_to_c = cis_config.max_pdu_p_to_c.unwrap_or(251);
        let sub_interval = (cig_config.iso_interval as u32 * 1250) / nse as u32;

        // Select one phy in the enabled mask with
        // the priority LE 2M > LE 1M > LE Coded.
        fn select_phy(phys: u8) -> u8 {
            match phys {
                0x2 | 0x3 | 0x6 | 0x7 => 0x2,
                0x1 | 0x5 => 0x1,
                0x4 => 0x4,
                0x0 => panic!(), // Not allowed by parameter LE Set Cig Parameters validation
                _ => unreachable!(),
            }
        }

        let phy_c_to_p = select_phy(cis_config.phy_c_to_p);
        let phy_p_to_c = select_phy(cis_config.phy_p_to_c);

        CisParameters {
            cig_sync_delay: cig_config.iso_interval as u32 * 1250,
            cis_sync_delay: cig_config.iso_interval as u32 * 1250,
            phy_c_to_p,
            phy_p_to_c,
            nse,
            bn_c_to_p,
            bn_p_to_c,
            ft_c_to_p: cig_config.ft_c_to_p,
            ft_p_to_c: cig_config.ft_p_to_c,
            max_pdu_c_to_p,
            max_pdu_p_to_c,
            max_sdu_c_to_p: cis_config.max_sdu_c_to_p,
            max_sdu_p_to_c: cis_config.max_sdu_p_to_c,
            sdu_interval_c_to_p: cig_config.sdu_interval_c_to_p,
            sdu_interval_p_to_c: cig_config.sdu_interval_p_to_c,
            iso_interval: cig_config.iso_interval,
            framed: cig_config.framed,
            sub_interval,
        }
    }

    fn phy_c_to_p(&self) -> hci::SecondaryPhyType {
        match self.phy_c_to_p {
            0x1 => hci::SecondaryPhyType::Le1m,
            0x2 => hci::SecondaryPhyType::Le2m,
            0x4 => hci::SecondaryPhyType::LeCoded,
            _ => unreachable!(),
        }
    }

    fn phy_p_to_c(&self) -> hci::SecondaryPhyType {
        match self.phy_p_to_c {
            0x1 => hci::SecondaryPhyType::Le1m,
            0x2 => hci::SecondaryPhyType::Le2m,
            0x4 => hci::SecondaryPhyType::LeCoded,
            _ => unreachable!(),
        }
    }

    fn transport_latency_c_to_p(&self) -> microseconds {
        transport_latency(
            self.cig_sync_delay,
            self.iso_interval,
            self.ft_c_to_p,
            self.sdu_interval_c_to_p,
            self.framed,
        )
    }

    fn transport_latency_p_to_c(&self) -> microseconds {
        transport_latency(
            self.cig_sync_delay,
            self.iso_interval,
            self.ft_p_to_c,
            self.sdu_interval_p_to_c,
            self.framed,
        )
    }
}

/// Established CIS configuration.
#[derive(Clone)]
pub struct Cis {
    pub cig_id: u8,
    pub cis_id: u8,
    pub role: hci::Role,
    pub cis_connection_handle: u16,
    pub acl_connection_handle: Option<u16>,
    pub state: CisState,
    parameters: Option<CisParameters>,
    iso_data_path_c_to_p: Option<IsoDataPath>,
    iso_data_path_p_to_c: Option<IsoDataPath>,
}

impl Cis {
    pub fn max_sdu_tx(&self) -> Option<u16> {
        self.parameters.as_ref().map(|parameters| match self.role {
            hci::Role::Central => parameters.max_sdu_c_to_p,
            hci::Role::Peripheral => parameters.max_sdu_p_to_c,
        })
    }
}

/// ISO manager state.
pub struct IsoManager {
    /// CIG configuration.
    cig_config: HashMap<u8, CigConfig>,
    /// CIS configuration.
    cis_config: HashMap<(u8, u8), CisConfig>,
    /// Mapping from ACL connection handle to connection role.
    acl_connections: HashMap<u16, hci::Role>,
    /// Mapping from CIS connection handle to a CIS connection
    /// opened as central (initiated a LL_CIS_REQ) or peripheral
    /// (accepted with LL_CIS_RSP). Central connections are in the
    /// configuration state as long as HCI LE Create CIS has not been
    /// invoked.
    cis_connections: HashMap<u16, Cis>,
    /// Pending CIS connection requests, initiated from the command
    /// HCI LE Create CIS.
    cis_connection_requests: Vec<CisRequest>,
    /// Link layer callbacks.
    ops: ffi::ControllerOps,
}

impl IsoManager {
    pub fn new(ops: ffi::ControllerOps) -> IsoManager {
        IsoManager {
            ops,
            cig_config: Default::default(),
            cis_config: Default::default(),
            acl_connections: Default::default(),
            cis_connections: Default::default(),
            cis_connection_requests: Default::default(),
        }
    }

    pub fn add_acl_connection(&mut self, acl_connection_handle: u16, role: hci::Role) {
        self.acl_connections.insert(acl_connection_handle, role);
    }

    pub fn remove_acl_connection(&mut self, acl_connection_handle: u16) {
        self.acl_connections.remove(&acl_connection_handle);
    }

    // Returns the first unused handle in the range 0xe00..0xefe.
    fn new_cis_connection_handle(&self) -> u16 {
        (0xe00..0xefe).find(|handle| !self.cis_connections.contains_key(handle)).unwrap()
    }

    // Insert a new CIS connection, optionally allocating an handle for the
    // selected CIG_Id, CIS_Id, Role triplet. Returns the handle for the connection.
    fn new_cis_connection(&mut self, cig_id: u8, cis_id: u8, role: hci::Role) -> u16 {
        let cis_connection_handle = self
            .cis_connections
            .values()
            .filter_map(|cis| {
                (cis.cig_id == cig_id && cis.cis_id == cis_id && cis.role == role)
                    .then_some(cis.cis_connection_handle)
            })
            .next();
        cis_connection_handle.unwrap_or_else(|| {
            let cis_connection_handle = self.new_cis_connection_handle();
            self.cis_connections.insert(
                cis_connection_handle,
                Cis {
                    cig_id,
                    cis_id,
                    role,
                    cis_connection_handle,
                    state: CisState::Configuration,
                    acl_connection_handle: None,
                    parameters: None,
                    iso_data_path_c_to_p: None,
                    iso_data_path_p_to_c: None,
                },
            );
            cis_connection_handle
        })
    }

    fn send_hci_event<E: Into<hci::Event>>(&self, event: E) {
        self.ops.send_hci_event(&event.into().to_vec())
    }

    fn send_llcp_packet<P: Into<llcp::LlcpPacket>>(&self, acl_connection_handle: u16, packet: P) {
        self.ops.send_llcp_packet(acl_connection_handle, &packet.into().to_vec())
    }

    fn get_le_features(&self) -> u64 {
        self.ops.get_le_features()
    }

    fn supported_phys(&self) -> u8 {
        let le_features = self.get_le_features();
        let mut supported_phys = 0x1;
        if (le_features & hci::LLFeaturesBits::Le2mPhy as u64) != 0 {
            supported_phys |= 0x2;
        }
        if (le_features & hci::LLFeaturesBits::LeCodedPhy as u64) != 0 {
            supported_phys |= 0x4;
        }
        supported_phys
    }

    fn connected_isochronous_stream_host_support(&self) -> bool {
        (self.get_le_features() & hci::LLFeaturesBits::ConnectedIsochronousStreamHostSupport as u64)
            != 0
    }

    pub fn get_cis_connection_handle<F>(&self, predicate: F) -> Option<u16>
    where
        F: Fn(&Cis) -> bool,
    {
        self.cis_connections
            .iter()
            .filter(|(_, cis)| predicate(cis))
            .map(|(handle, _)| handle)
            .next()
            .cloned()
    }

    pub fn get_cis(&self, cis_connection_handle: u16) -> Option<&Cis> {
        self.cis_connections.get(&cis_connection_handle)
    }

    /// Start the next CIS connection request, if any.
    fn deque_cis_connection_request(&mut self) {
        if let Some(request) = self.cis_connection_requests.pop() {
            let cis_config = self.cis_config.get(&(request.cig_id, request.cis_id)).unwrap();
            let cig_config = self.cig_config.get(&request.cig_id).unwrap();
            let parameters = CisParameters::new(cig_config, cis_config);

            self.send_llcp_packet(
                request.acl_connection_handle,
                llcp::CisReqBuilder {
                    cig_id: request.cig_id,
                    cis_id: request.cis_id,
                    phy_c_to_p: parameters.phy_c_to_p,
                    phy_p_to_c: parameters.phy_p_to_c,
                    framed: cig_config.framed as u8,
                    max_sdu_c_to_p: cis_config.max_sdu_c_to_p,
                    max_sdu_p_to_c: cis_config.max_sdu_p_to_c,
                    sdu_interval_c_to_p: cig_config.sdu_interval_c_to_p,
                    sdu_interval_p_to_c: cig_config.sdu_interval_p_to_c,
                    max_pdu_c_to_p: parameters.max_pdu_c_to_p,
                    max_pdu_p_to_c: parameters.max_pdu_p_to_c,
                    nse: parameters.nse,
                    sub_interval: parameters.sub_interval,
                    bn_c_to_p: parameters.bn_c_to_p,
                    bn_p_to_c: parameters.bn_p_to_c,
                    ft_c_to_p: cig_config.ft_c_to_p,
                    ft_p_to_c: cig_config.ft_p_to_c,
                    iso_interval: cig_config.iso_interval,
                    cis_offset_min: 0,
                    cis_offset_max: 0,
                    conn_event_count: 0,
                },
            );

            let cis = self.cis_connections.get_mut(&request.cis_connection_handle).unwrap();
            cis.acl_connection_handle = Some(request.acl_connection_handle);
            cis.state = CisState::PendingRsp;
            cis.parameters = Some(parameters);
        }
    }

    pub fn hci_le_set_cig_parameters(&mut self, packet: hci::LeSetCigParameters) {
        let cig_id: u8 = packet.get_cig_id();
        let sdu_interval_c_to_p: u32 = packet.get_sdu_interval_c_to_p();
        let sdu_interval_p_to_c: u32 = packet.get_sdu_interval_p_to_c();
        let framed: bool = packet.get_framing() == hci::Enable::Enabled;
        let max_transport_latency_c_to_p: u16 = packet.get_max_transport_latency_c_to_p();
        let max_transport_latency_p_to_c: u16 = packet.get_max_transport_latency_p_to_c();
        let cis_config: &[hci::CisParametersConfig] = packet.get_cis_config();

        let command_complete = |status| hci::LeSetCigParametersCompleteBuilder {
            status,
            cig_id,
            connection_handle: vec![],
            num_hci_command_packets: 1,
        };

        // If the Host issues this command when the CIG is not in the configurable
        // state, the Controller shall return the error code
        // Command Disallowed (0x0C).
        if !self.cig_config.get(&cig_id).map(|cig| cig.configurable).unwrap_or(true) {
            println!("CIG ({}) is no longer in the configurable state", cig_id);
            return self.send_hci_event(command_complete(hci::ErrorCode::CommandDisallowed));
        }

        for cis in cis_config {
            let cis_id = cis.cis_id;
            let cis_connection = self.cis_connections.values().find(|cis| {
                cis.cis_id == cis_id && cis.cig_id == cig_id && cis.role == hci::Role::Central
            });
            let (iso_data_path_c_to_p, iso_data_path_p_to_c) = cis_connection
                .map(|cis| (cis.iso_data_path_c_to_p, cis.iso_data_path_p_to_c))
                .unwrap_or((None, None));

            // The PHY_C_To_P[i] parameter identifies which PHY to use for transmission
            // from the Central to the Peripheral. The Host shall set at least one bit in this
            // parameter and the Controller shall pick a PHY from the bits that are set.
            if cis.phy_c_to_p == 0 || cis.phy_p_to_c == 0 {
                println!(
                    "CIS ({}) does not configure PHys ({:x}, {:x})",
                    cis.cis_id, cis.phy_c_to_p, cis.phy_p_to_c
                );
                return self.send_hci_event(command_complete(
                    hci::ErrorCode::UnsupportedFeatureOrParameterValue,
                ));
            }

            // If the Host sets, in the PHY_C_To_P[i] or PHY_P_To_C[i] parameters, a bit
            // for a PHY that the Controller does not support, including a bit that is
            // reserved for future use, the Controller shall return the error code
            // Unsupported Feature or Parameter Value (0x11).
            if (cis.phy_c_to_p & !self.supported_phys()) != 0
                || (cis.phy_p_to_c & !self.supported_phys()) != 0
            {
                println!(
                    "CIS ({}) configures unsupported PHYs ({:x}, {:x})",
                    cis.cis_id, cis.phy_c_to_p, cis.phy_p_to_c
                );
                return self.send_hci_event(command_complete(
                    hci::ErrorCode::UnsupportedFeatureOrParameterValue,
                ));
            }

            // If a CIS configuration that is being modified has a data path set in
            // the Central to Peripheral direction and the Host has specified
            // that Max_SDU_C_To_P[i] shall be set to zero, the Controller shall
            // return the error code Command Disallowed (0x0C).
            if cis.max_sdu_c_to_p == 0 && iso_data_path_c_to_p.is_some() {
                println!(
                    "CIS ({}) has a data path for C->P but Max_SDU_C_To_P is zero",
                    cis.cis_id
                );
                return self.send_hci_event(command_complete(hci::ErrorCode::CommandDisallowed));
            }

            // If a CIS configuration that is being modified has a data path set in the
            // Peripheral to Central direction and the Host has specified that
            // Max_SDU_P_To_C[i] shall be set to zero, the Controller shall return
            // the error code Command Disallowed (0x0C).
            if cis.max_sdu_p_to_c == 0 && iso_data_path_p_to_c.is_some() {
                println!(
                    "CIS ({}) has a data path for P->C but Max_SDU_P_To_C is zero",
                    cis.cis_id
                );
                return self.send_hci_event(command_complete(hci::ErrorCode::CommandDisallowed));
            }

            if cis.max_sdu_c_to_p > 0xfff || cis.max_sdu_p_to_c > 0xfff {
                println!(
                    "invalid Max_SDU C->P ({}) or Max_SDU P->C ({}) for CIS ({})",
                    cis.max_sdu_c_to_p, cis.max_sdu_p_to_c, cis_id
                );
                return self
                    .send_hci_event(command_complete(hci::ErrorCode::InvalidHciCommandParameters));
            }
        }

        let configures_c_to_p = cis_config.iter().any(|cis| cis.max_sdu_c_to_p != 0)
            || self.cis_config.iter().any(|(key, cis)| {
                key.0 == cig_id
                    && cis.max_sdu_c_to_p != 0
                    && cis_config.iter().all(|new_cis| new_cis.cis_id != key.1)
            });
        let configures_p_to_c = cis_config.iter().any(|cis| cis.max_sdu_p_to_c != 0)
            || self.cis_config.iter().any(|(key, cis)| {
                key.0 == cig_id
                    && cis.max_sdu_p_to_c != 0
                    && cis_config.iter().all(|new_cis| new_cis.cis_id != key.1)
            });

        // If the Host specifies an invalid combination of CIS parameters, the
        // Controller shall return the error code Unsupported Feature or
        // Parameter Value (0x11).
        if (configures_c_to_p && !(0xff..=0xf_ffff).contains(&sdu_interval_c_to_p))
            || (configures_p_to_c && !(0xff..=0xf_ffff).contains(&sdu_interval_p_to_c))
        {
            println!(
                "invalid SDU_Interval C->P ({}) or SDU_Interval P->C ({})",
                sdu_interval_c_to_p, sdu_interval_p_to_c
            );
            return self
                .send_hci_event(command_complete(hci::ErrorCode::InvalidHciCommandParameters));
        }
        if (configures_c_to_p && !(0x5..=0xfa0).contains(&max_transport_latency_c_to_p))
            || (configures_p_to_c && !(0x5..=0xfa0).contains(&max_transport_latency_p_to_c))
        {
            println!(
                "invalid Max_Transport_Latency C->P ({}) or Max_Transport_Latency P->C ({})",
                max_transport_latency_c_to_p, max_transport_latency_p_to_c
            );
            return self
                .send_hci_event(command_complete(hci::ErrorCode::InvalidHciCommandParameters));
        }

        let Some(iso_interval) = iso_interval(
            sdu_interval_c_to_p,
            sdu_interval_p_to_c,
            framed,
            max_transport_latency_c_to_p as u32 * 1000,
            max_transport_latency_p_to_c as u32 * 1000,
        ) else {
            println!(
                "ISO_Interval cannot be chosen that fulfills the requirement from the CIG parameters");
            return self.send_hci_event(command_complete(
                hci::ErrorCode::UnsupportedFeatureOrParameterValue,
            ));
        };

        // If the Status return parameter is non-zero, then the state of the CIG
        // and its CIS configurations shall not be changed by the command.
        // If the CIG did not already exist, it shall not be created.
        let cig = self.cig_config.entry(cig_id).or_default();
        let mut cis_connection_handles = vec![];
        cig.iso_interval = iso_interval;
        cig.sdu_interval_c_to_p = sdu_interval_c_to_p;
        cig.sdu_interval_p_to_c = sdu_interval_p_to_c;
        cig.ft_c_to_p = 1;
        cig.ft_p_to_c = 1;
        cig.framed = framed;

        for cis_config in cis_config {
            self.cis_config.insert(
                (cig_id, cis_config.cis_id),
                CisConfig {
                    max_sdu_c_to_p: cis_config.max_sdu_c_to_p,
                    max_sdu_p_to_c: cis_config.max_sdu_p_to_c,
                    phy_c_to_p: cis_config.phy_c_to_p,
                    phy_p_to_c: cis_config.phy_p_to_c,
                    nse: None,
                    bn_c_to_p: None,
                    bn_p_to_c: None,
                    max_pdu_c_to_p: None,
                    max_pdu_p_to_c: None,
                },
            );

            let cis_connection_handle =
                self.new_cis_connection(cig_id, cis_config.cis_id, hci::Role::Central);
            cis_connection_handles.push(cis_connection_handle);
        }

        self.send_hci_event(hci::LeSetCigParametersCompleteBuilder {
            status: hci::ErrorCode::Success,
            cig_id,
            connection_handle: cis_connection_handles,
            num_hci_command_packets: 1,
        })
    }

    pub fn hci_le_set_cig_parameters_test(&mut self, packet: hci::LeSetCigParametersTest) {
        let cig_id: u8 = packet.get_cig_id();
        let sdu_interval_c_to_p: u32 = packet.get_sdu_interval_c_to_p();
        let sdu_interval_p_to_c: u32 = packet.get_sdu_interval_p_to_c();
        let ft_c_to_p: u8 = packet.get_ft_c_to_p();
        let ft_p_to_c: u8 = packet.get_ft_p_to_c();
        let iso_interval: u16 = packet.get_iso_interval();
        let framed: bool = packet.get_framing() == hci::Enable::Enabled;
        let cis_config: &[hci::LeCisParametersTestConfig] = packet.get_cis_config();

        let command_complete = |status| hci::LeSetCigParametersTestCompleteBuilder {
            status,
            cig_id,
            connection_handle: vec![],
            num_hci_command_packets: 1,
        };

        // If the Host issues this command when the CIG is not in the configurable
        // state, the Controller shall return the error code
        // Command Disallowed (0x0C).
        if !self.cig_config.get(&cig_id).map(|cig| cig.configurable).unwrap_or(true) {
            println!("CIG ({}) is no longer in the configurable state", cig_id);
            return self.send_hci_event(command_complete(hci::ErrorCode::CommandDisallowed));
        }

        for cis in cis_config {
            let cis_id = cis.cis_id;
            let cis_connection = self.cis_connections.values().find(|cis| {
                cis.cis_id == cis_id && cis.cig_id == cig_id && cis.role == hci::Role::Central
            });
            let (iso_data_path_c_to_p, iso_data_path_p_to_c) = cis_connection
                .map(|cis| (cis.iso_data_path_c_to_p, cis.iso_data_path_p_to_c))
                .unwrap_or((None, None));

            // The PHY_C_To_P[i] parameter identifies which PHY to use for transmission
            // from the Central to the Peripheral. The Host shall set at least one bit in this
            // parameter and the Controller shall pick a PHY from the bits that are set.
            if cis.phy_c_to_p == 0 || cis.phy_p_to_c == 0 {
                println!(
                    "CIS ({}) does not configure PHys ({:x}, {:x})",
                    cis.cis_id, cis.phy_c_to_p, cis.phy_p_to_c
                );
                return self.send_hci_event(command_complete(
                    hci::ErrorCode::UnsupportedFeatureOrParameterValue,
                ));
            }

            // If the Host sets, in the PHY_C_To_P[i] or PHY_P_To_C[i] parameters, a bit
            // for a PHY that the Controller does not support, including a bit that is
            // reserved for future use, the Controller shall return the error code
            // Unsupported Feature or Parameter Value (0x11).
            if (cis.phy_c_to_p & !self.supported_phys()) != 0
                || (cis.phy_p_to_c & !self.supported_phys()) != 0
            {
                println!(
                    "CIS ({}) configures unsupported PHYs ({:x}, {:x})",
                    cis.cis_id, cis.phy_c_to_p, cis.phy_p_to_c
                );
                return self.send_hci_event(command_complete(
                    hci::ErrorCode::UnsupportedFeatureOrParameterValue,
                ));
            }

            // If a CIS configuration that is being modified has a data path set in
            // the Central to Peripheral direction and the Host has specified
            // that Max_SDU_C_To_P[i] shall be set to zero, the Controller shall
            // return the error code Command Disallowed (0x0C).
            if cis.max_sdu_c_to_p == 0 && iso_data_path_c_to_p.is_some() {
                println!(
                    "CIS ({}) has a data path for C->P but Max_SDU_C_To_P is zero",
                    cis.cis_id
                );
                return self.send_hci_event(command_complete(hci::ErrorCode::CommandDisallowed));
            }

            // If a CIS configuration that is being modified has a data path set in the
            // Peripheral to Central direction and the Host has specified that
            // Max_SDU_P_To_C[i] shall be set to zero, the Controller shall return
            // the error code Command Disallowed (0x0C).
            if cis.max_sdu_p_to_c == 0 && iso_data_path_p_to_c.is_some() {
                println!(
                    "CIS ({}) has a data path for P->C but Max_SDU_P_To_C is zero",
                    cis.cis_id
                );
                return self.send_hci_event(command_complete(hci::ErrorCode::CommandDisallowed));
            }

            if cis.max_sdu_c_to_p > 0xfff || cis.max_sdu_p_to_c > 0xfff {
                println!(
                    "invalid Max_SDU C->P ({}) or Max_SDU P->C ({}) for CIS ({})",
                    cis.max_sdu_c_to_p, cis.max_sdu_p_to_c, cis_id
                );
                return self
                    .send_hci_event(command_complete(hci::ErrorCode::InvalidHciCommandParameters));
            }
        }

        let configures_c_to_p = cis_config.iter().any(|cis| cis.max_sdu_c_to_p != 0)
            || self.cis_config.iter().any(|(key, cis)| {
                key.0 == cig_id
                    && cis.max_sdu_c_to_p != 0
                    && cis_config.iter().all(|new_cis| new_cis.cis_id != key.1)
            });
        let configures_p_to_c = cis_config.iter().any(|cis| cis.max_sdu_p_to_c != 0)
            || self.cis_config.iter().any(|(key, cis)| {
                key.0 == cig_id
                    && cis.max_sdu_p_to_c != 0
                    && cis_config.iter().all(|new_cis| new_cis.cis_id != key.1)
            });

        // If the Host specifies an invalid combination of CIS parameters, the
        // Controller shall return the error code Unsupported Feature or
        // Parameter Value (0x11).
        if (configures_c_to_p && !(0xff..=0xf_ffff).contains(&sdu_interval_c_to_p))
            || (configures_p_to_c && !(0xff..=0xf_ffff).contains(&sdu_interval_p_to_c))
        {
            println!(
                "invalid SDU_Interval C->P ({}) or SDU_Interval P->C ({})",
                sdu_interval_c_to_p, sdu_interval_p_to_c
            );
            return self
                .send_hci_event(command_complete(hci::ErrorCode::InvalidHciCommandParameters));
        }

        // If the Status return parameter is non-zero, then the state of the CIG
        // and its CIS configurations shall not be changed by the command.
        // If the CIG did not already exist, it shall not be created.
        let cig = self.cig_config.entry(cig_id).or_default();
        let mut cis_connection_handles = vec![];
        cig.iso_interval = iso_interval;
        cig.sdu_interval_c_to_p = sdu_interval_c_to_p;
        cig.sdu_interval_p_to_c = sdu_interval_p_to_c;
        cig.ft_c_to_p = ft_c_to_p;
        cig.ft_p_to_c = ft_p_to_c;
        cig.framed = framed;

        for cis_config in cis_config {
            self.cis_config.insert(
                (cig_id, cis_config.cis_id),
                CisConfig {
                    max_sdu_c_to_p: cis_config.max_sdu_c_to_p,
                    max_sdu_p_to_c: cis_config.max_sdu_p_to_c,
                    phy_c_to_p: cis_config.phy_c_to_p,
                    phy_p_to_c: cis_config.phy_p_to_c,
                    nse: Some(cis_config.nse),
                    bn_c_to_p: Some(cis_config.bn_c_to_p),
                    bn_p_to_c: Some(cis_config.bn_p_to_c),
                    max_pdu_c_to_p: Some(cis_config.max_pdu_c_to_p),
                    max_pdu_p_to_c: Some(cis_config.max_pdu_p_to_c),
                },
            );

            let cis_connection_handle =
                self.new_cis_connection(cig_id, cis_config.cis_id, hci::Role::Central);
            cis_connection_handles.push(cis_connection_handle);
        }

        self.send_hci_event(hci::LeSetCigParametersTestCompleteBuilder {
            status: hci::ErrorCode::Success,
            cig_id,
            connection_handle: cis_connection_handles,
            num_hci_command_packets: 1,
        })
    }

    pub fn hci_le_remove_cig(&mut self, packet: hci::LeRemoveCig) {
        let cig_id: u8 = packet.get_cig_id();

        let command_complete =
            |status| hci::LeRemoveCigCompleteBuilder { status, cig_id, num_hci_command_packets: 1 };

        // If the Host issues this command with a CIG_ID that does not exist, the
        // Controller shall return the error code Unknown Connection Identifier (0x02).
        if !self.cig_config.contains_key(&cig_id) {
            println!("CIG ({}) does not exist", cig_id);
            return self.send_hci_event(command_complete(hci::ErrorCode::UnknownConnection));
        }

        // If the Host tries to remove a CIG which is in the active state,
        // then the Controller shall return the error code
        // Command Disallowed (0x0C).
        if self.cis_connections.values().any(|cis| {
            cis.role == hci::Role::Central
                && cis.cig_id == cig_id
                && cis.state != CisState::Configuration
        }) {
            println!("CIG ({}) cannot be removed as it is in active state", cig_id);
            return self.send_hci_event(command_complete(hci::ErrorCode::CommandDisallowed));
        }

        // Clear the CIG configuration.
        self.cig_config.remove(&cig_id);
        self.cis_config.retain(|key, _| key.0 != cig_id);

        // Remove the CIS connections.
        self.cis_connections
            .retain(|_, cis| cis.role != hci::Role::Central || cis.cig_id != cig_id);

        self.send_hci_event(command_complete(hci::ErrorCode::Success))
    }

    pub fn hci_le_create_cis(&mut self, packet: hci::LeCreateCis) {
        let cis_config: &[hci::LeCreateCisConfig] = packet.get_cis_config();
        let mut cis_connection_requests: Vec<CisRequest> = vec![];

        let command_status =
            |status| hci::LeCreateCisStatusBuilder { status, num_hci_command_packets: 1 };

        for cis_config in cis_config {
            match self.acl_connections.get(&cis_config.acl_connection_handle) {
                // If any ACL_Connection_Handle[i] is not the handle of an existing ACL
                // connection, the Controller shall return the error code Unknown Connection
                // Identifier (0x02).
                None => {
                    println!(
                        "cannot create LE CIS with unknown ACL connection handle {}",
                        cis_config.acl_connection_handle
                    );
                    return self.send_hci_event(command_status(hci::ErrorCode::UnknownConnection));
                }
                // If the Host issues this command on an ACL_Connection_Handle where the
                // Controller is the Peripheral, the Controller shall return the error code
                // Command Disallowed (0x0C).
                Some(hci::Role::Peripheral) => {
                    println!(
                        "the ACL connection handle {} is for a peripheral connection",
                        cis_config.acl_connection_handle
                    );
                    return self.send_hci_event(command_status(
                        hci::ErrorCode::InvalidHciCommandParameters,
                    ));
                }
                Some(hci::Role::Central) => (),
            }

            // If any CIS_Connection_Handle[i] is not the handle of a CIS or CIS
            // configuration, the Controller shall return the error code Unknown Connection
            // Identifier (0x02).
            let Some(cis) = self.cis_connections.get(&cis_config.cis_connection_handle) else {
                println!(
                    "cannot create LE CIS with unknown CIS connection handle {}",
                    cis_config.cis_connection_handle
                );
                return self.send_hci_event(command_status(hci::ErrorCode::UnknownConnection));
            };

            // If the Host attempts to create a CIS that has already been created, the
            // Controller shall return the error code Connection Already Exists (0x0B).
            if cis.state != CisState::Configuration {
                println!(
                    "cannot create LE CIS with CIS connection handle {} as it is already connected",
                    cis_config.cis_connection_handle
                );
                return self
                    .send_hci_event(command_status(hci::ErrorCode::ConnectionAlreadyExists));
            }

            // If two different elements of the CIS_Connection_Handle arrayed parameter
            // identify the same CIS, the Controller shall return the error code
            // Invalid HCI Command Parameters (0x12).
            if cis_connection_requests
                .iter()
                .any(|request| request.cis_connection_handle == cis_config.cis_connection_handle)
            {
                println!(
                    "the CIS connection handle {} is requested twice",
                    cis_config.cis_connection_handle
                );
                return self
                    .send_hci_event(command_status(hci::ErrorCode::InvalidHciCommandParameters));
            }

            cis_connection_requests.push(CisRequest {
                cis_connection_handle: cis_config.cis_connection_handle,
                acl_connection_handle: cis_config.acl_connection_handle,
                cig_id: cis.cig_id,
                cis_id: cis.cis_id,
            });
        }

        // If the Host issues this command before all the HCI_LE_CIS_Established
        // events from the previous use of the command have been generated, the
        // Controller shall return the error code Command Disallowed (0x0C).
        if !self.cis_connection_requests.is_empty() {
            println!("another LE Create CIS request is already pending");
            return self.send_hci_event(command_status(hci::ErrorCode::CommandDisallowed));
        }

        // If the Host issues this command when the Connected Isochronous Stream
        // (Host Support) feature bit (see [Vol 6] Part B, Section 4.6.27) is not set,
        // the Controller shall return the error code Command Disallowed (0x0C).
        if !self.connected_isochronous_stream_host_support() {
            println!("the feature bit Connected Isochronous Stream (Host Support) is not set");
            return self.send_hci_event(command_status(hci::ErrorCode::CommandDisallowed));
        }

        // Update the pending CIS request list.
        cis_connection_requests.reverse();
        self.cis_connection_requests = cis_connection_requests;

        // Send the first connection request.
        self.deque_cis_connection_request();
        self.send_hci_event(command_status(hci::ErrorCode::Success))
    }

    pub fn hci_le_accept_cis_request(&mut self, packet: hci::LeAcceptCisRequest) {
        let connection_handle: u16 = packet.get_connection_handle();

        let command_status =
            |status| hci::LeAcceptCisRequestStatusBuilder { status, num_hci_command_packets: 1 };

        // If the Peripheral’s Host issues this command with a
        // Connection_Handle that does not exist, or the Connection_Handle
        // is not for a CIS, the Controller shall return the error code
        // Unknown Connection Identifier (0x02).
        if !self.cis_connections.contains_key(&connection_handle) {
            println!(
                "cannot accept LE CIS request with invalid connection handle {}",
                connection_handle
            );
            return self.send_hci_event(command_status(hci::ErrorCode::UnknownConnection));
        }

        let cis = self.cis_connections.get_mut(&connection_handle).unwrap();

        // If the Central’s Host issues this command, the Controller shall
        // return the error code Command Disallowed (0x0C).
        if cis.role == hci::Role::Central {
            println!(
                "cannot accept LE CIS request with central connection handle {}",
                connection_handle
            );
            return self.send_hci_event(command_status(hci::ErrorCode::CommandDisallowed));
        }

        // If the Peripheral's Host issues this command with a Connection_Handle
        // for a CIS that has already been established or that already has an
        // HCI_LE_Accept_CIS_Request or HCI_LE_Reject_CIS_Request command in progress,
        // the Controller shall return the error code Command Disallowed (0x0C).
        if cis.state != CisState::PendingAccept {
            println!(
                "cannot accept LE CIS request for non-pending connection handle {}",
                connection_handle
            );
            return self.send_hci_event(command_status(hci::ErrorCode::CommandDisallowed));
        }

        // Update local state.
        cis.state = CisState::PendingInd;

        // Send back LL_CIS_RSP to accept the request.
        let acl_connection_handle = cis.acl_connection_handle.unwrap();
        self.send_llcp_packet(
            acl_connection_handle,
            llcp::CisRspBuilder {
                cis_offset_min: 0,
                cis_offset_max: 0xffffff,
                conn_event_count: 0,
            },
        );

        self.send_hci_event(command_status(hci::ErrorCode::Success))
    }

    pub fn hci_le_reject_cis_request(&mut self, packet: hci::LeRejectCisRequest) {
        let connection_handle: u16 = packet.get_connection_handle();

        let command_complete = |status| hci::LeRejectCisRequestCompleteBuilder {
            status,
            connection_handle,
            num_hci_command_packets: 1,
        };

        // If the Peripheral’s Host issues this command with a
        // Connection_Handle that does not exist, or the Connection_Handle
        // is not for a CIS, the Controller shall return the error code
        // Unknown Connection Identifier (0x02).
        if !self.cis_connections.contains_key(&connection_handle) {
            println!(
                "cannot accept LE CIS request with invalid connection handle {}",
                connection_handle
            );
            return self.send_hci_event(command_complete(hci::ErrorCode::UnknownConnection));
        }

        let cis = self.cis_connections.get(&connection_handle).unwrap();

        // If the Central’s Host issues this command, the Controller shall
        // return the error code Command Disallowed (0x0C).
        if cis.role == hci::Role::Central {
            println!(
                "cannot accept LE CIS request with central connection handle {}",
                connection_handle
            );
            return self.send_hci_event(command_complete(hci::ErrorCode::CommandDisallowed));
        }

        // If the Peripheral's Host issues this command with a Connection_Handle
        // for a CIS that has already been established or that already has an
        // HCI_LE_Accept_CIS_Request or HCI_LE_Reject_CIS_Request command in progress,
        // the Controller shall return the error code Command Disallowed (0x0C).
        if cis.state != CisState::PendingAccept {
            println!(
                "cannot accept LE CIS request for non-pending connection handle {}",
                connection_handle
            );
            return self.send_hci_event(command_complete(hci::ErrorCode::CommandDisallowed));
        }

        // Update local state.
        let acl_connection_handle = cis.acl_connection_handle.unwrap();
        self.cis_connections.remove(&connection_handle);

        // Send back LL_CIS_RSP to reject the request.
        let error_code = if packet.get_reason() == hci::ErrorCode::Success {
            hci::ErrorCode::RemoteUserTerminatedConnection
        } else {
            packet.get_reason()
        };
        self.send_llcp_packet(
            acl_connection_handle,
            llcp::RejectExtIndBuilder {
                reject_opcode: llcp::Opcode::LlCisReq as u8,
                error_code: error_code as u8,
            },
        );

        self.send_hci_event(command_complete(hci::ErrorCode::Success))
    }

    pub fn hci_le_setup_iso_data_path(&mut self, packet: hci::LeSetupIsoDataPath) {
        let connection_handle: u16 = packet.get_connection_handle();
        let codec_configuration = packet.get_codec_configuration();

        let command_complete = |status| hci::LeSetupIsoDataPathCompleteBuilder {
            status,
            connection_handle,
            num_hci_command_packets: 1,
        };

        // If the Host attempts to set a data path with a Connection Handle that does not
        // exist or that is not for a CIS, CIS configuration, or BIS, the Controller shall
        // return the error code Unknown Connection Identifier (0x02).
        let Some(cis) = self.cis_connections.get_mut(&connection_handle) else {
            println!("the CIS connection handle 0x{:x} is not assigned", connection_handle);
            return self.send_hci_event(command_complete(hci::ErrorCode::CommandDisallowed));
        };

        let (c_to_p_direction, p_to_c_direction) = if cis.role == hci::Role::Central {
            (hci::DataPathDirection::Output, hci::DataPathDirection::Input)
        } else {
            (hci::DataPathDirection::Input, hci::DataPathDirection::Output)
        };

        // If the Host issues this command more than once for the same
        // Connection_Handle and direction before issuing the HCI_LE_Remove_ISO_Data_-
        // Path command for that Connection_Handle and direction, the Controller shall
        // return the error code Command Disallowed (0x0C).
        if cis.iso_data_path_c_to_p.is_some()
            && packet.get_data_path_direction() == c_to_p_direction
        {
            println!("C->P ISO data path already configured for ({}, {})", cis.cig_id, cis.cis_id);
            return self.send_hci_event(command_complete(hci::ErrorCode::CommandDisallowed));
        }
        if cis.iso_data_path_p_to_c.is_some()
            && packet.get_data_path_direction() == p_to_c_direction
        {
            println!("P->C ISO data path already configured for ({}, {})", cis.cig_id, cis.cis_id);
            return self.send_hci_event(command_complete(hci::ErrorCode::CommandDisallowed));
        }

        // If the Host issues this command for a CIS on a Peripheral before it has issued
        // the HCI_LE_Accept_CIS_Request command for that CIS, then the Controller
        // shall return the error code Command Disallowed (0x0C).
        if cis.role == hci::Role::Peripheral && cis.state == CisState::PendingAccept {
            println!("setup ISO data path sent before accepting the CIS request");
            return self.send_hci_event(command_complete(hci::ErrorCode::CommandDisallowed));
        }

        // If the Host issues this command for a vendor-specific data transport path that
        // has not been configured using the HCI_Configure_Data_Path command, the
        // Controller shall return the error code Command Disallowed (0x0C).

        // If the Host attempts to set an output data path using a connection handle that is
        // for an Isochronous Broadcaster, for an input data path on a Synchronized
        // Receiver, or for a data path for the direction on a unidirectional CIS where BN
        // is set to 0, the Controller shall return the error code Command Disallowed
        // (0x0C).

        // If the Host issues this command with Codec_Configuration_Length non-zero
        // and Codec_ID set to transparent air mode, the Controller shall return the error
        // code Invalid HCI Command Parameters (0x12).
        if !codec_configuration.is_empty() && packet.get_codec_id() == 0x3 {
            println!("Codec Configuration is not empty and Codec ID is for transparent air mode");
            return self
                .send_hci_event(command_complete(hci::ErrorCode::InvalidHciCommandParameters));
        }

        // If the Host issues this command with codec-related parameters that exceed the
        // bandwidth and latency allowed on the established CIS or BIS identified by the
        // Connection_Handle parameter, the Controller shall return the error code
        // Invalid HCI Command Parameters (0x12).

        if packet.get_data_path_direction() == c_to_p_direction {
            cis.iso_data_path_c_to_p = Some(IsoDataPath::Hci);
        } else {
            cis.iso_data_path_p_to_c = Some(IsoDataPath::Hci);
        }

        self.send_hci_event(command_complete(hci::ErrorCode::Success))
    }

    pub fn hci_le_remove_iso_data_path(&mut self, packet: hci::LeRemoveIsoDataPath) {
        let connection_handle: u16 = packet.get_connection_handle();
        let data_path_direction = packet.get_remove_data_path_direction();

        let command_complete = |status| hci::LeRemoveIsoDataPathCompleteBuilder {
            status,
            connection_handle,
            num_hci_command_packets: 1,
        };

        // If the Host issues this command with a Connection_Handle that does not exist
        // or is not for a CIS, CIS configuration, or BIS, the Controller shall return the
        // error code Unknown Connection Identifier (0x02).
        let Some(cis) = self.cis_connections.get_mut(&connection_handle) else {
            println!("the CIS connection handle 0x{:x} is not assigned", connection_handle);
            return self.send_hci_event(command_complete(hci::ErrorCode::CommandDisallowed));
        };

        let (remove_c_to_p, remove_p_to_c) = if cis.role == hci::Role::Central {
            (
                data_path_direction == hci::RemoveDataPathDirection::Output
                    || data_path_direction == hci::RemoveDataPathDirection::InputAndOutput,
                data_path_direction == hci::RemoveDataPathDirection::Input
                    || data_path_direction == hci::RemoveDataPathDirection::InputAndOutput,
            )
        } else {
            (
                data_path_direction == hci::RemoveDataPathDirection::Input
                    || data_path_direction == hci::RemoveDataPathDirection::InputAndOutput,
                data_path_direction == hci::RemoveDataPathDirection::Output
                    || data_path_direction == hci::RemoveDataPathDirection::InputAndOutput,
            )
        };

        // If the Host issues this command for a data path that has not been set up (using
        // the HCI_LE_Setup_ISO_Data_Path command), the Controller shall return the
        // error code Command Disallowed (0x0C)
        if cis.iso_data_path_c_to_p.is_none() && remove_c_to_p {
            println!("attempted to remove Iso Data Path C->P but it is not configured");
            return self.send_hci_event(command_complete(hci::ErrorCode::CommandDisallowed));
        }
        if cis.iso_data_path_p_to_c.is_none() && remove_p_to_c {
            println!("attempted to remove Iso Data Path P->C but it is not configured");
            return self.send_hci_event(command_complete(hci::ErrorCode::CommandDisallowed));
        }

        if remove_c_to_p {
            cis.iso_data_path_c_to_p = None;
        }
        if remove_p_to_c {
            cis.iso_data_path_p_to_c = None;
        }

        self.send_hci_event(command_complete(hci::ErrorCode::Success))
    }

    pub fn hci_disconnect(&mut self, packet: hci::Disconnect) {
        let connection_handle: u16 = packet.get_connection_handle();
        let command_status =
            |status| hci::DisconnectStatusBuilder { status, num_hci_command_packets: 1 };

        let Some(cis) = self.cis_connections.get(&connection_handle).cloned() else {
            return self.send_hci_event(command_status(hci::ErrorCode::UnknownConnection));
        };

        // If, on the Central, the Host issues this command before issuing the
        // HCI_LE_Create_CIS command for the same CIS, then the Controller shall
        // return the error code Command Disallowed (0x0C).
        // If, on the Peripheral, the Host issues this command before the Controller has
        // generated the HCI_LE_CIS_Established event for that CIS, then the Controller
        // shall return the error code Command Disallowed (0x0C).
        if !matches!(cis.state, CisState::Connected | CisState::PendingRsp) {
            println!(
                "cannot disconnect CIS connection with handle {} because it is not connected",
                connection_handle
            );
            return self.send_hci_event(command_status(hci::ErrorCode::CommandDisallowed));
        }

        if cis.role == hci::Role::Central {
            self.cis_connections
                .entry(connection_handle)
                .and_modify(|cis| cis.state = CisState::Configuration);
        } else {
            self.cis_connections.remove(&connection_handle);
        }

        self.send_llcp_packet(
            cis.acl_connection_handle.unwrap(),
            llcp::CisTerminateIndBuilder {
                cig_id: cis.cig_id,
                cis_id: cis.cis_id,
                error_code: packet.get_reason().into(),
            },
        );

        self.send_hci_event(command_status(hci::ErrorCode::Success));
        self.send_hci_event(hci::DisconnectionCompleteBuilder {
            status: hci::ErrorCode::Success,
            connection_handle,
            reason: hci::ErrorCode::ConnectionTerminatedByLocalHost,
        });
    }

    pub fn ll_cis_req(&mut self, acl_connection_handle: u16, packet: llcp::CisReq) {
        let cis_connection_handle = self.new_cis_connection_handle();
        self.cis_connections.insert(
            cis_connection_handle,
            Cis {
                cig_id: packet.get_cig_id(),
                cis_id: packet.get_cis_id(),
                role: hci::Role::Peripheral,
                acl_connection_handle: Some(acl_connection_handle),
                cis_connection_handle,
                state: CisState::PendingAccept,
                iso_data_path_c_to_p: None,
                iso_data_path_p_to_c: None,
                parameters: Some(CisParameters {
                    cig_sync_delay: 0,
                    cis_sync_delay: 0,
                    phy_c_to_p: packet.get_phy_c_to_p(),
                    phy_p_to_c: packet.get_phy_p_to_c(),
                    nse: packet.get_nse(),
                    bn_c_to_p: packet.get_bn_c_to_p(),
                    bn_p_to_c: packet.get_bn_p_to_c(),
                    ft_c_to_p: packet.get_ft_c_to_p(),
                    ft_p_to_c: packet.get_ft_p_to_c(),
                    max_pdu_c_to_p: packet.get_max_pdu_c_to_p(),
                    max_pdu_p_to_c: packet.get_max_pdu_p_to_c(),
                    max_sdu_c_to_p: packet.get_max_sdu_c_to_p(),
                    max_sdu_p_to_c: packet.get_max_sdu_p_to_c(),
                    sdu_interval_c_to_p: packet.get_sdu_interval_c_to_p(),
                    sdu_interval_p_to_c: packet.get_sdu_interval_p_to_c(),
                    iso_interval: packet.get_iso_interval(),
                    sub_interval: packet.get_sub_interval(),
                    framed: packet.get_framed() != 0,
                }),
            },
        );

        self.send_hci_event(hci::LeCisRequestBuilder {
            acl_connection_handle,
            cis_connection_handle,
            cig_id: packet.get_cig_id(),
            cis_id: packet.get_cis_id(),
        })
    }

    pub fn ll_cis_rsp(&mut self, acl_connection_handle: u16, _packet: llcp::CisRsp) {
        let cis_connection_handle = self.get_cis_connection_handle(|cis| {
            cis.acl_connection_handle == Some(acl_connection_handle)
                && cis.role == hci::Role::Central
                && cis.state == CisState::PendingRsp
        });

        if let Some(cis_connection_handle) = cis_connection_handle {
            self.cis_connections
                .entry(cis_connection_handle)
                .and_modify(|cis| cis.state = CisState::Connected);
            let cis = self.cis_connections.get(&cis_connection_handle).unwrap();
            let parameters = cis.parameters.as_ref().unwrap();
            self.send_llcp_packet(
                acl_connection_handle,
                llcp::CisIndBuilder {
                    aa: 0,
                    cis_offset: 0,
                    cig_sync_delay: parameters.cig_sync_delay,
                    cis_sync_delay: parameters.cis_sync_delay,
                    conn_event_count: 0,
                },
            );
            self.send_hci_event(hci::LeCisEstablishedBuilder {
                status: hci::ErrorCode::Success,
                connection_handle: cis_connection_handle,
                cig_sync_delay: parameters.cig_sync_delay,
                cis_sync_delay: parameters.cis_sync_delay,
                transport_latency_c_to_p: parameters.transport_latency_c_to_p(),
                transport_latency_p_to_c: parameters.transport_latency_p_to_c(),
                phy_c_to_p: parameters.phy_c_to_p(),
                phy_p_to_c: parameters.phy_p_to_c(),
                nse: parameters.nse,
                bn_c_to_p: parameters.bn_c_to_p,
                bn_p_to_c: parameters.bn_p_to_c,
                ft_c_to_p: parameters.ft_c_to_p,
                ft_p_to_c: parameters.ft_p_to_c,
                max_pdu_c_to_p: parameters.max_pdu_c_to_p as u8,
                max_pdu_p_to_c: parameters.max_pdu_p_to_c as u8,
                iso_interval: parameters.iso_interval,
            });
            // Start the next pending connection request.
            self.deque_cis_connection_request();
        } else {
            println!("skipping out of place packet LL_CIS_RSP");
        }
    }

    pub fn ll_reject_ext_ind(&mut self, acl_connection_handle: u16, packet: llcp::RejectExtInd) {
        if packet.get_reject_opcode() != llcp::Opcode::LlCisReq as u8 {
            return;
        }

        let cis_connection_handle = self.get_cis_connection_handle(|cis| {
            cis.acl_connection_handle == Some(acl_connection_handle)
                && cis.role == hci::Role::Central
                && cis.state == CisState::PendingRsp
        });

        if let Some(cis_connection_handle) = cis_connection_handle {
            let cis = self.cis_connections.get_mut(&cis_connection_handle).unwrap();
            cis.state = CisState::Configuration;
            cis.parameters = None;
            self.send_hci_event(hci::LeCisEstablishedBuilder {
                status: hci::ErrorCode::RemoteUserTerminatedConnection,
                connection_handle: cis_connection_handle,
                cig_sync_delay: 0,
                cis_sync_delay: 0,
                transport_latency_c_to_p: 0,
                transport_latency_p_to_c: 0,
                phy_c_to_p: hci::SecondaryPhyType::NoPackets,
                phy_p_to_c: hci::SecondaryPhyType::NoPackets,
                nse: 0,
                bn_p_to_c: 0,
                bn_c_to_p: 0,
                ft_p_to_c: 0,
                ft_c_to_p: 0,
                max_pdu_p_to_c: 0,
                max_pdu_c_to_p: 0,
                iso_interval: 0,
            });
            // Start the next pending connection request.
            self.deque_cis_connection_request();
        } else {
            println!("skipping out of place packet LL_CIS_IND");
        }
    }

    pub fn ll_cis_ind(&mut self, acl_connection_handle: u16, packet: llcp::CisInd) {
        let cis_connection_handle = self.get_cis_connection_handle(|cis| {
            cis.acl_connection_handle == Some(acl_connection_handle)
                && cis.role == hci::Role::Peripheral
                && cis.state == CisState::PendingInd
        });

        if let Some(cis_connection_handle) = cis_connection_handle {
            self.cis_connections.entry(cis_connection_handle).and_modify(|cis| {
                cis.state = CisState::Connected;
                let parameters = cis.parameters.as_mut().unwrap();
                parameters.cig_sync_delay = packet.get_cig_sync_delay();
                parameters.cis_sync_delay = packet.get_cis_sync_delay();
            });
            let cis = self.cis_connections.get(&cis_connection_handle).unwrap();
            let parameters = cis.parameters.as_ref().unwrap();
            self.send_hci_event(hci::LeCisEstablishedBuilder {
                status: hci::ErrorCode::Success,
                connection_handle: cis_connection_handle,
                cig_sync_delay: parameters.cig_sync_delay,
                cis_sync_delay: parameters.cis_sync_delay,
                transport_latency_c_to_p: parameters.transport_latency_c_to_p(),
                transport_latency_p_to_c: parameters.transport_latency_p_to_c(),
                phy_c_to_p: parameters.phy_c_to_p(),
                phy_p_to_c: parameters.phy_p_to_c(),
                nse: parameters.nse,
                bn_p_to_c: parameters.bn_c_to_p,
                bn_c_to_p: parameters.bn_p_to_c,
                ft_p_to_c: parameters.ft_c_to_p,
                ft_c_to_p: parameters.ft_p_to_c,
                max_pdu_p_to_c: parameters.max_pdu_c_to_p as u8,
                max_pdu_c_to_p: parameters.max_pdu_p_to_c as u8,
                iso_interval: parameters.iso_interval,
            });
        } else {
            println!("skipping out of place packet LL_CIS_IND");
        }
    }

    pub fn ll_cis_terminate_ind(
        &mut self,
        acl_connection_handle: u16,
        packet: llcp::CisTerminateInd,
    ) {
        let cis_connection_handle = self.get_cis_connection_handle(|cis| {
            cis.acl_connection_handle == Some(acl_connection_handle)
                && cis.cig_id == packet.get_cig_id()
                && cis.cis_id == packet.get_cis_id()
        });

        if let Some(cis_connection_handle) = cis_connection_handle {
            self.send_hci_event(hci::DisconnectionCompleteBuilder {
                status: hci::ErrorCode::Success,
                connection_handle: cis_connection_handle,
                reason: hci::ErrorCode::try_from(packet.get_error_code()).unwrap(),
            });
            self.cis_connections.remove(&cis_connection_handle);
        } else {
            println!("skipping out of place packet LL_CIS_TERMINATE_IND");
        }
    }
}

/// Derive a valid ISO_Interval for a CIG based on the
/// LE Set Cig Parameters command input. SDU_Interval, Max_Transport_Latency are
/// provided microseconds.
fn iso_interval(
    sdu_interval_c_to_p: microseconds,
    sdu_interval_p_to_c: microseconds,
    framed: bool,
    max_transport_latency_c_to_p: microseconds,
    max_transport_latency_p_to_c: microseconds,
) -> Option<slots> {
    if framed {
        let iso_interval = std::cmp::max(sdu_interval_c_to_p, sdu_interval_p_to_c);
        Some(((iso_interval + 1249) / 1250) as u16)
    } else {
        // Unframed PDUs shall only be used when the ISO_Interval is equal to
        // or an integer multiple of the SDU_Interval and a constant time offset
        // alignment is maintained between the SDU generation and the timing in
        // the isochronous transport.
        let iso_interval = num_integer::lcm(
            1250,
            match (sdu_interval_c_to_p, sdu_interval_p_to_c) {
                (0, 0) => panic!(),
                (0, _) => sdu_interval_p_to_c,
                (_, 0) => sdu_interval_c_to_p,
                _ => num_integer::lcm(sdu_interval_c_to_p, sdu_interval_p_to_c),
            },
        );
        let min_transport_latency_c_to_p = 2 * iso_interval - sdu_interval_c_to_p;
        let min_transport_latency_p_to_c = 2 * iso_interval - sdu_interval_p_to_c;

        ((iso_interval / 1250) <= u16::MAX as u32
            && (sdu_interval_c_to_p == 0
                || min_transport_latency_c_to_p <= max_transport_latency_c_to_p)
            && (sdu_interval_p_to_c == 0
                || min_transport_latency_p_to_c <= max_transport_latency_p_to_c))
            .then_some((iso_interval / 1250) as u16)
    }
}

/// Compute the transport latency for a CIG based on the
/// configuration parameters. CIG_Sync_Delay, SDU_Interval are provided
/// in microseconds, ISO_Interval in multiple of 1.25ms,
fn transport_latency(
    cig_sync_delay: microseconds,
    iso_interval: slots,
    ft: u8,
    sdu_interval: microseconds,
    framed: bool,
) -> microseconds {
    let iso_interval = iso_interval as u32 * 1250;
    if framed {
        cig_sync_delay + ft as u32 * iso_interval + sdu_interval
    } else {
        cig_sync_delay + ft as u32 * iso_interval - sdu_interval
    }
}

#[cfg(test)]
mod test {
    use crate::llcp::iso::*;

    #[test]
    fn test_iso_interval() {
        assert!(iso_interval(0x7530, 0x7530, false, 0x7530, 0x7530).is_some());
        assert!(iso_interval(0x7530, 0, false, 0x7530, 0x7530).is_some());
        assert!(iso_interval(0x7530, 0x7530, false, 0x7000, 0x7000).is_none());
    }
}
