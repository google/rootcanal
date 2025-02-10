# RootCanal

Binding to the RootCanal controller implementation. Enables virtual testing
of Bluetooth applications directly in Python.

## Supported platforms

- `linux-x86_64`
- `macos-arm64`

## Usage

```bash
python -m rootcanal [OPTION]
```

Command line options include:
- `-configuration` (controller configuration (see config.proto))
    type: string
    default: ""
- `-configuration_file` (controller configuration file path (see config.proto))
    type: string default: ""
- `-disable_address_reuse` (prevent rootcanal from reusing device addresses)
  type: bool default: false
- `-enable_baseband_sniffer` (enable baseband sniffer) type: bool
  default: false
- `-enable_hci_sniffer` (enable hci sniffer) type: bool default: false
- `-enable_log_color` (enable log colors) type: bool default: false
- `-enable_pcap_filter` (enable PCAP filter) type: bool default: false
- `-hci_port` (hci server tcp port) type: uint32 default: 6402
- `-link_ble_port` (le link server tcp port) type: uint32 default: 6404
- `-link_port` (link server tcp port) type: uint32 default: 6403
- `-test_port` (test tcp port) type: uint32 default: 6401

## Example

Example python script to emulate a successful connection establishment
for an instance of the RootCanal controller.

```python
import asyncio
from rootcanal.controller import Controller, Any
from rootcanal.bluetooth import Address
from rootcanal.packets import hci
from rootcanal.packets import ll
from rootcanal.packets import llcp
from rootcanal.packets import lmp


async def test():
    controller = Controller(Address("11:11:11:11:11:11"))
    await controller.start()

    # Send HCI Reset to the controller and wait for the response.
    controller.send_cmd(hci.Reset())
    _ = await controller.expect_evt(
        hci.ResetComplete(status=hci.ErrorCode.SUCCESS, num_hci_command_packets=1)
    )

    # Check the local address.
    controller.send_cmd(hci.ReadBdAddr())
    _ = await controller.expect_evt(
        hci.ReadBdAddrComplete(
            status=hci.ErrorCode.SUCCESS,
            num_hci_command_packets=1,
            bd_addr=Address("11:11:11:11:11:11"),
        )
    )

    # Enable page scan.
    controller.send_cmd(hci.WriteScanEnable(scan_enable=hci.ScanEnable.PAGE_SCAN_ONLY))
    _ = await controller.expect_evt(
        hci.WriteScanEnableComplete(
            status=hci.ErrorCode.SUCCESS, num_hci_command_packets=1
        )
    )

    # Send classic connection request.
    controller.send_ll(
        ll.Page(
            class_of_device=0,
            allow_role_switch=0,
            source_address=Address("22:22:22:22:22:22"),
            destination_address=Address("11:11:11:11:11:11"),
        )
    )
    _ = await controller.expect_evt(
        hci.ConnectionRequest(
            bd_addr=Address("22:22:22:22:22:22"),
            class_of_device=0,
            link_type=hci.ConnectionRequestLinkType.ACL,
        )
    )

    # Accept the connection request.
    controller.send_cmd(
        hci.AcceptConnectionRequest(
            bd_addr=Address("22:22:22:22:22:22"),
            role=hci.AcceptConnectionRequestRole.REMAIN_PERIPHERAL,
        )
    )
    _ = await controller.expect_evt(
        hci.AcceptConnectionRequestStatus(
            status=hci.ErrorCode.SUCCESS, num_hci_command_packets=1
        )
    )

    _ = await controller.expect_ll(
        ll.PageResponse(
            source_address=Address("11:11:11:11:11:11"),
            destination_address=Address("22:22:22:22:22:22"),
            try_role_switch=0,
        )
    )

    _ = await controller.expect_evt(
        hci.ConnectionComplete(
            status=hci.ErrorCode.SUCCESS,
            connection_handle=Any(),
            bd_addr=Address("22:22:22:22:22:22"),
            link_type=hci.LinkType.ACL,
            encryption_enabled=hci.Enable.DISABLED,
        )
    )

    controller.stop()


asyncio.get_event_loop().run_until_complete(test())
```
