# Introduction

RootCanal is a virtual Bluetooth Controller. RootCanal aims reducing the
overhead of writing and deploying end-to-end tests on Bluetooth devices
by taking away the physical layer.

The emulation of Bluetooth features on RootCanal _is limited to features
that have direct consequences on connected hosts_. The accurate implementation
of HCI commands and events is thus critical to RootCanal's goal, while accurate
emulation of the scheduler and base-band is out of scope.

## Usage

RootCanal can be natively built or installed pre-compiled though the PyPI
`rootcanal` package. Both options have been tested with `linux-x86_64` and
`macos-arm64`, `windows` is not yet supported.

### Build instructions

```
sudo apt install bazel rustc cargo
cargo install pdl-compiler --version 0.3.2
```

```
git clone https://github.com/google/rootcanal.git
cd rootcanal
git submodule update --init
bazel run :rootcanal
```

### Python instructions

```
pip install rootcanal
python -m rootcanal
```

### Launch options

The following configuration options are implemented:

* `--test_port` (default `6401`) Configure the TCP port for the test channel.

* `--hci_port` (default `6402`) Configure the TCP port for the HCI server.

* `--link_port` (default `6403`) Configure the TCP port for the link server.

* `--link_ble_port` (default `6404`) Configure the TCP port for the BLE link server.

* `--controller_properties_file` (default `""`) Configure the path to
a custom Controller configuration file. All properties defined in
`model/controller/controller_properties.h` can be edited to test with a
specific controller setup. The format of the configuration file is defined
by `proto/rootcanal/configuration.proto`

* `--enable_hci_sniffer` (default `false`) Capture PCAP traces for all
connected HCI hosts. The PCAP traces are saved in the current directory.

* `--enable_baseband_sniffer` (default `false`) Capture PCAP traces for all
base-band packets exchanged between connection HCI hosts. The PCAP traces are
saved in the current directory. This option is useful to inspect and debug
RootCanal's implementation.

# Architecture

All RootCanal instances expose four TCP ports:
- _HCI channel_
- _Test channel_
- _BR_EDR Phy channel_
- _LE Phy channel_

## HCI Channel

The HCI channel implements the Bluetooth UART transport protocol
(a.k.a. H4) over TCP. Each new connection on the HCI port spawns a new virtual
controller.

## Test Channel

The test channel uses a simple custom protocol to send control commands
to RootCanal. You can connect to it using [scripts/test_channel.py](scripts/test_channel.py).

## Phy Channels

The physical channels use a custom protocol described in [packets/link_layer_packets.pdl](packets/link_layer_packets.pdl).
The protocol simplifies the LL and LMP protocol packets defined in the Bluetooth
specification to abstract over negotiation details.

**Warning** The protocol can change in backward incompatible ways,
be careful when depending on it.

Controllers can exchanges link layer packets only when they are part of the
same phy. One controller can be added to multiple phys, the simplest example
begin BR/EDR and LE dual phys.

# Supported features

## HCI Commands

| Command name                                                 | Supported     |
|--------------------------------------------------------------|---------------|
| Inquiry                                                      | Yes           |
| Inquiry Cancel                                               | Yes           |
| Periodic Inquiry Mode                                        | No            |
| Exit Periodic Inquiry Mode                                   | No            |
| Create Connection                                            | Yes           |
| Disconnect                                                   | Yes           |
| Add Sco Connection                                           | Yes           |
| Create Connection Cancel                                     | Yes           |
| Accept Connection Request                                    | Yes           |
| Reject Connection Request                                    | Yes           |
| Link Key Request Reply                                       | Yes           |
| Link Key Request Negative Reply                              | Yes           |
| Pin Code Request Reply                                       | Yes           |
| Pin Code Request Negative Reply                              | Yes           |
| Change Connection Packet Type                                | Yes           |
| Authentication Requested                                     | Yes           |
| Set Connection Encryption                                    | Yes           |
| Change Connection Link Key                                   | Yes           |
| Central Link Key                                             | Yes           |
| Remote Name Request                                          | Yes           |
| Remote Name Request Cancel                                   | No            |
| Read Remote Supported Features                               | Yes           |
| Read Remote Extended Features                                | Yes           |
| Read Remote Version Information                              | Yes           |
| Read Clock Offset                                            | Yes           |
| Read Lmp Handle                                              | No            |
| Setup Synchronous Connection                                 | Yes           |
| Accept Synchronous Connection                                | Yes           |
| Reject Synchronous Connection                                | Yes           |
| Io Capability Request Reply                                  | Yes           |
| User Confirmation Request Reply                              | Yes           |
| User Confirmation Request Negative Reply                     | Yes           |
| User Passkey Request Reply                                   | Yes           |
| User Passkey Request Negative Reply                          | Yes           |
| Remote Oob Data Request Reply                                | Yes           |
| Remote Oob Data Request Negative Reply                       | Yes           |
| Io Capability Request Negative Reply                         | Yes           |
| Enhanced Setup Synchronous Connection                        | Yes           |
| Enhanced Accept Synchronous Connection                       | Yes           |
| Truncated Page                                               | No            |
| Truncated Page Cancel                                        | No            |
| Set Connectionless Peripheral Broadcast                      | No            |
| Set Connectionless Peripheral Broadcast Receive              | No            |
| Start Synchronization Train                                  | No            |
| Receive Synchronization Train                                | No            |
| Remote Oob Extended Data Request Reply                       | Yes           |
| Hold Mode                                                    | Yes           |
| Sniff Mode                                                   | Yes           |
| Exit Sniff Mode                                              | Yes           |
| Qos Setup                                                    | Yes           |
| Role Discovery                                               | Yes           |
| Switch Role                                                  | Yes           |
| Read Link Policy Settings                                    | Yes           |
| Write Link Policy Settings                                   | Yes           |
| Read Default Link Policy Settings                            | Yes           |
| Write Default Link Policy Settings                           | Yes           |
| Flow Specification                                           | Yes           |
| Sniff Subrating                                              | Yes           |
| Set Event Mask                                               | Yes           |
| Reset                                                        | Yes           |
| Set Event Filter                                             | Yes           |
| Flush                                                        | No            |
| Read Pin Type                                                | No            |
| Write Pin Type                                               | No            |
| Read Stored Link Key                                         | No            |
| Write Stored Link Key                                        | No            |
| Delete Stored Link Key                                       | Yes           |
| Write Local Name                                             | Yes           |
| Read Local Name                                              | Yes           |
| Read Connection Accept Timeout                               | Yes           |
| Write Connection Accept Timeout                              | Yes           |
| Read Page Timeout                                            | Yes           |
| Write Page Timeout                                           | Yes           |
| Read Scan Enable                                             | Yes           |
| Write Scan Enable                                            | Yes           |
| Read Page Scan Activity                                      | Yes           |
| Write Page Scan Activity                                     | Yes           |
| Read Inquiry Scan Activity                                   | Yes           |
| Write Inquiry Scan Activity                                  | Yes           |
| Read Authentication Enable                                   | Yes           |
| Write Authentication Enable                                  | Yes           |
| Read Class Of Device                                         | Yes           |
| Write Class Of Device                                        | Yes           |
| Read Voice Setting                                           | Yes           |
| Write Voice Setting                                          | Yes           |
| Read Automatic Flush Timeout                                 | No            |
| Write Automatic Flush Timeout                                | No            |
| Read Num Broadcast Retransmits                               | No            |
| Write Num Broadcast Retransmits                              | No            |
| Read Hold Mode Activity                                      | No            |
| Write Hold Mode Activity                                     | No            |
| Read Transmit Power Level                                    | Yes           |
| Read Synchronous Flow Control Enable                         | Yes           |
| Write Synchronous Flow Control Enable                        | Yes           |
| Set Controller To Host Flow Control                          | No            |
| Host Buffer Size                                             | Yes           |
| Host Number Of Completed Packets                             | No            |
| Read Link Supervision Timeout                                | No            |
| Write Link Supervision Timeout                               | Yes           |
| Read Number Of Supported Iac                                 | Yes           |
| Read Current Iac Lap                                         | Yes           |
| Write Current Iac Lap                                        | Yes           |
| Set Afh Host Channel Classification                          | No            |
| Read Inquiry Scan Type                                       | Yes           |
| Write Inquiry Scan Type                                      | Yes           |
| Read Inquiry Mode                                            | Yes           |
| Write Inquiry Mode                                           | Yes           |
| Read Page Scan Type                                          | Yes           |
| Write Page Scan Type                                         | Yes           |
| Read Afh Channel Assessment Mode                             | No            |
| Write Afh Channel Assessment Mode                            | No            |
| Read Extended Inquiry Response                               | No            |
| Write Extended Inquiry Response                              | Yes           |
| Refresh Encryption Key                                       | Yes           |
| Read Simple Pairing Mode                                     | No            |
| Write Simple Pairing Mode                                    | Yes           |
| Read Local Oob Data                                          | Yes           |
| Read Inquiry Response Transmit Power Level                   | Yes           |
| Write Inquiry Transmit Power Level                           | No            |
| Read Default Erroneous Data Reporting                        | No            |
| Write Default Erroneous Data Reporting                       | No            |
| Enhanced Flush                                               | Yes           |
| Send Keypress Notification                                   | Yes           |
| Set Event Mask Page 2                                        | Yes           |
| Read Flow Control Mode                                       | No            |
| Write Flow Control Mode                                      | No            |
| Read Enhanced Transmit Power Level                           | Yes           |
| Read Le Host Support                                         | No            |
| Write Le Host Support                                        | Yes           |
| Set Mws Channel Parameters                                   | No            |
| Set External Frame Configuration                             | No            |
| Set Mws Signaling                                            | No            |
| Set Mws Transport Layer                                      | No            |
| Set Mws Scan Frequency Table                                 | No            |
| Set Mws Pattern Configuration                                | No            |
| Set Reserved Lt Addr                                         | No            |
| Delete Reserved Lt Addr                                      | No            |
| Set Connectionless Peripheral Broadcast Data                 | No            |
| Read Synchronization Train Parameters                        | No            |
| Write Synchronization Train Parameters                       | No            |
| Read Secure Connections Host Support                         | No            |
| Write Secure Connections Host Support                        | Yes           |
| Read Authenticated Payload Timeout                           | No            |
| Write Authenticated Payload Timeout                          | No            |
| Read Local Oob Extended Data                                 | Yes           |
| Read Extended Page Timeout                                   | No            |
| Write Extended Page Timeout                                  | No            |
| Read Extended Inquiry Length                                 | No            |
| Write Extended Inquiry Length                                | No            |
| Set Ecosystem Base Interval                                  | No            |
| Configure Data Path                                          | No            |
| Set Min Encryption Key Size                                  | No            |
| Read Local Version Information                               | Yes           |
| Read Local Supported Commands                                | Yes           |
| Read Local Supported Features                                | Yes           |
| Read Local Extended Features                                 | Yes           |
| Read Buffer Size                                             | Yes           |
| Read Bd Addr                                                 | Yes           |
| Read Data Block Size                                         | No            |
| Read Local Supported Codecs V1                               | Yes           |
| Read Local Simple Pairing Options                            | No            |
| Read Local Supported Codecs V2                               | No            |
| Read Local Supported Codec Capabilities                      | No            |
| Read Local Supported Controller Delay                        | No            |
| Read Failed Contact Counter                                  | Yes           |
| Reset Failed Contact Counter                                 | Yes           |
| Read Link Quality                                            | No            |
| Read Rssi                                                    | Yes           |
| Read Afh Channel Map                                         | No            |
| Read Clock                                                   | No            |
| Read Encryption Key Size                                     | Yes           |
| Get Mws Transport Layer Configuration                        | No            |
| Set Triggered Clock Capture                                  | No            |
| Read Loopback Mode                                           | Yes           |
| Write Loopback Mode                                          | Yes           |
| Enable Device Under Test Mode                                | No            |
| Write Simple Pairing Debug Mode                              | No            |
| Write Secure Connections Test Mode                           | No            |
| LE Set Event Mask                                            | Yes           |
| LE Read Buffer Size V1                                       | Yes           |
| LE Read Local Supported Features                             | Yes           |
| LE Set Random Address                                        | Yes           |
| LE Set Advertising Parameters                                | Yes           |
| LE Read Advertising Physical Channel Tx Power                | Yes           |
| LE Set Advertising Data                                      | Yes           |
| LE Set Scan Response Data                                    | Yes           |
| LE Set Advertising Enable                                    | Yes           |
| LE Set Scan Parameters                                       | Yes           |
| LE Set Scan Enable                                           | Yes           |
| LE Create Connection                                         | Yes           |
| LE Create Connection Cancel                                  | Yes           |
| LE Read Filter Accept List Size                              | Yes           |
| LE Clear Filter Accept List                                  | Yes           |
| LE Add Device To Filter Accept List                          | Yes           |
| LE Remove Device From Filter Accept List                     | Yes           |
| LE Connection Update                                         | Yes           |
| LE Set Host Channel Classification                           | No            |
| LE Read Channel Map                                          | No            |
| LE Read Remote Features                                      | Yes           |
| LE Encrypt                                                   | Yes           |
| LE Rand                                                      | Yes           |
| LE Start Encryption                                          | Yes           |
| LE Long Term Key Request Reply                               | Yes           |
| LE Long Term Key Request Negative Reply                      | Yes           |
| LE Read Supported States                                     | Yes           |
| LE Receiver Test V1                                          | No            |
| LE Transmitter Test V1                                       | No            |
| LE Test End                                                  | No            |
| LE Remote Connection Parameter Request Reply                 | Yes           |
| LE Remote Connection Parameter Request Negative Reply        | Yes           |
| LE Set Data Length                                           | No            |
| LE Read Suggested Default Data Length                        | Yes           |
| LE Write Suggested Default Data Length                       | Yes           |
| LE Read Local P 256 Public Key                               | No            |
| LE Generate Dhkey V1                                         | No            |
| LE Add Device To Resolving List                              | Yes           |
| LE Remove Device From Resolving List                         | Yes           |
| LE Clear Resolving List                                      | Yes           |
| LE Read Resolving List Size                                  | Yes           |
| LE Read Peer Resolvable Address                              | Yes           |
| LE Read Local Resolvable Address                             | Yes           |
| LE Set Address Resolution Enable                             | Yes           |
| LE Set Resolvable Private Address Timeout                    | Yes           |
| LE Read Maximum Data Length                                  | Yes           |
| LE Read Phy                                                  | Yes           |
| LE Set Default Phy                                           | Yes           |
| LE Set Phy                                                   | Yes           |
| LE Receiver Test V2                                          | No            |
| LE Transmitter Test V2                                       | No            |
| LE Set Advertising Set Random Address                        | Yes           |
| LE Set Extended Advertising Parameters                       | Yes           |
| LE Set Extended Advertising Data                             | Yes           |
| LE Set Extended Scan Response Data                           | Yes           |
| LE Set Extended Advertising Enable                           | Yes           |
| LE Read Maximum Advertising Data Length                      | Yes           |
| LE Read Number Of Supported Advertising Sets                 | Yes           |
| LE Remove Advertising Set                                    | Yes           |
| LE Clear Advertising Sets                                    | Yes           |
| LE Set Periodic Advertising Parameters                       | Yes           |
| LE Set Periodic Advertising Data                             | Yes           |
| LE Set Periodic Advertising Enable                           | Yes           |
| LE Set Extended Scan Parameters                              | Yes           |
| LE Set Extended Scan Enable                                  | Yes           |
| LE Extended Create Connection                                | Yes           |
| LE Periodic Advertising Create Sync                          | Yes           |
| LE Periodic Advertising Create Sync Cancel                   | Yes           |
| LE Periodic Advertising Terminate Sync                       | Yes           |
| LE Add Device To Periodic Advertiser List                    | Yes           |
| LE Remove Device From Periodic Advertiser List               | Yes           |
| LE Clear Periodic Advertiser List                            | Yes           |
| LE Read Periodic Advertiser List Size                        | Yes           |
| LE Read Transmit Power                                       | No            |
| LE Read Rf Path Compensation Power                           | No            |
| LE Write Rf Path Compensation Power                          | No            |
| LE Set Privacy Mode                                          | Yes           |
| LE Receiver Test V3                                          | No            |
| LE Transmitter Test V3                                       | No            |
| LE Set Connectionless Cte Transmit Parameters                | No            |
| LE Set Connectionless Cte Transmit Enable                    | No            |
| LE Set Connectionless Iq Sampling Enable                     | No            |
| LE Set Connection Cte Receive Parameters                     | No            |
| LE Set Connection Cte Transmit Parameters                    | No            |
| LE Connection Cte Request Enable                             | No            |
| LE Connection Cte Response Enable                            | No            |
| LE Read Antenna Information                                  | No            |
| LE Set Periodic Advertising Receive Enable                   | No            |
| LE Periodic Advertising Sync Transfer                        | No            |
| LE Periodic Advertising Set Info Transfer                    | No            |
| LE Set Periodic Advertising Sync Transfer Parameters         | No            |
| LE Set Default Periodic Advertising Sync Transfer Parameters | No            |
| LE Generate Dhkey V2                                         | No            |
| LE Modify Sleep Clock Accuracy                               | No            |
| LE Read Buffer Size V2                                       | Yes           |
| LE Read Iso Tx Sync                                          | No            |
| LE Set Cig Parameters                                        | Yes           |
| LE Set Cig Parameters Test                                   | Yes           |
| LE Create Cis                                                | Yes           |
| LE Remove Cig                                                | Yes           |
| LE Accept Cis Request                                        | Yes           |
| LE Reject Cis Request                                        | Yes           |
| LE Create Big                                                | No            |
| LE Create Big Test                                           | No            |
| LE Terminate Big                                             | No            |
| LE Big Create Sync                                           | No            |
| LE Big Terminate Sync                                        | No            |
| LE Request Peer Sca                                          | Yes           |
| LE Setup Iso Data Path                                       | Yes           |
| LE Remove Iso Data Path                                      | No            |
| LE Iso Transmit Test                                         | No            |
| LE Iso Receive Test                                          | No            |
| LE Iso Read Test Counters                                    | No            |
| LE Iso Test End                                              | No            |
| LE Set Host Feature                                          | Yes           |
| LE Read Iso Link Quality                                     | No            |
| LE Enhanced Read Transmit Power Level                        | No            |
| LE Read Remote Transmit Power Level                          | No            |
| LE Set Path Loss Reporting Parameters                        | No            |
| LE Set Path Loss Reporting Enable                            | No            |
| LE Set Transmit Power Reporting Enable                       | No            |
| LE Transmitter Test V4                                       | No            |
| LE Set Data Related Address Changes                          | No            |
| LE Set Default Subrate                                       | No            |
| LE Subrate Request                                           | No            |
