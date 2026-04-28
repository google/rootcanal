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
by `proto/rootcanal/configuration.proto`.

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

- LL Privacy
- Extended Advertising
- Periodic Advertising
- Channel Sounding (under development)
- Connection Subrating
- LE Power Control Requests
- Connected Isochronous Stream
- Broadcast Isochronous Stream (under development)
