# RootCanal

Binding to the RootCanal controller implementation. Enables virtual testing
of Bluetooth applications directly in Python.

## Usage

```python
from rootcanal.controller import Controller
from rootcanal.bluetooth import Address
import hci_packets as hci
import llcp_packets as llcp
import lmp_packets as lmp
import ll_packets as ll

controller = Controller::new(Address("ca:fe:ca:fe:00:00"))

# Send HCI Reset to the controller and wait for the response.
controller.send_cmd(hci.Reset())
_ = await controller.expect_evt(hci.ResetCommplete)

# Enable page scan.
controller.send_cmd(hci.WriteScanEnable(scan_enable=hci.ScanEnable.PAGE_SCAN_ONLY))
_ = await controller.expect_evt(hci.WriteScanEnableComplete)

# Send classic connection request.
controller.send_ll(
    ll.Page(
        class_of_device=0,
        allow_role_switch=0,
        source_address=Address("11:11:11:11:11:11")))
_ = await controller.expect_evt(hci.ConnectionRequest)

# Accept the connection request.
_ = await controller.send_cmd(
    hci.AcceptConnectionRequest(
        bd_addr=Address("11:11:11:11:11:11"),
        role=hci.AcceptConnectionRequestRole.REMAIN_PERIPHERAL))
_ = await controller.expect_evt(hci.AcceptConnectionRequestStatus)
_ = await controller.expect_ll(hci.PageResponse)
_ = await controller.expect_evt(hci.ConnectionComplete)
```
