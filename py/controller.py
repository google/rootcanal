import asyncio
import collections
import hci_packets as hci
import lib_rootcanal_python3 as rootcanal
import link_layer_packets as ll
import py.bluetooth
import unittest
from typing import Optional
from hci_packets import ErrorCode


class LeFeatures:

    def __init__(self, le_features: int):
        self.mask = le_features
        self.ll_privacy = (le_features & hci.LLFeaturesBits.LL_PRIVACY) != 0
        self.le_extended_advertising = (le_features & hci.LLFeaturesBits.LE_EXTENDED_ADVERTISING) != 0


class Controller(rootcanal.BaseController):
    """Binder class to DualModeController.
    The methods send_cmd, send_hci, send_ll are used to inject HCI or LL
    packets into the controller, and receive_hci, receive_ll to
    catch outgoing HCI packets of LL pdus."""

    def __init__(self, address: hci.Address):
        super().__init__(repr(address), self.receive_hci_, self.receive_ll_)
        self.address = address
        self.evt_queue = collections.deque()
        self.acl_queue = collections.deque()
        self.ll_queue = collections.deque()
        self.evt_queue_event = asyncio.Event()
        self.acl_queue_event = asyncio.Event()
        self.ll_queue_event = asyncio.Event()

    def receive_hci_(self, typ: rootcanal.HciType, packet: bytes):
        if typ == rootcanal.HciType.Evt:
            print(f"<-- received HCI event data={len(packet)}[..]")
            self.evt_queue.append(packet)
            self.loop.call_soon_threadsafe(self.evt_queue_event.set)
        elif typ == rootcanal.HciType.Acl:
            print(f"<-- received HCI ACL packet data={len(packet)}[..]")
            self.acl_queue.append(packet)
            self.loop.call_soon_threadsafe(self.acl_queue_event.set)
        else:
            print(f"ignoring HCI packet typ={typ}")

    def receive_ll_(self, packet: bytes):
        print(f"<-- received LL pdu data={len(packet)}[..]")
        self.ll_queue.append(packet)
        self.loop.call_soon_threadsafe(self.ll_queue_event.set)

    def send_cmd(self, cmd: hci.Command):
        print(f"--> sending HCI command {cmd.__class__.__name__}")
        self.send_hci(rootcanal.HciType.Cmd, cmd.serialize())

    def send_ll(self, pdu: ll.LinkLayerPacket, rssi: int = -90):
        print(f"--> sending LL pdu {pdu.__class__.__name__}")
        super().send_ll(pdu.serialize(), rssi)

    async def start(self):
        super().start()
        self.loop = asyncio.get_event_loop()

    def stop(self):
        super().stop()
        if self.evt_queue:
            print("evt queue not empty at stop():")
            for packet in self.evt_queue:
                evt = hci.Event.parse_all(packet)
                evt.show()
            raise Exception("evt queue not empty at stop()")

        if self.ll_queue:
            for (packet, _) in self.ll_queue:
                pdu = ll.LinkLayerPacket.parse_all(packet)
                pdu.show()
            raise Exception("ll queue not empty at stop()")

    async def receive_evt(self):
        while not self.evt_queue:
            await self.evt_queue_event.wait()
            self.evt_queue_event.clear()
        return self.evt_queue.popleft()

    async def expect_evt(self, expected_evt: hci.Event):
        packet = await self.receive_evt()
        evt = hci.Event.parse_all(packet)
        if evt != expected_evt:
            print("received unexpected event")
            print("expected event:")
            expected_evt.show()
            print("received event:")
            evt.show()
            raise Exception(f"unexpected evt {evt.__class__.__name__}")

    async def receive_ll(self):
        while not self.ll_queue:
            await self.ll_queue_event.wait()
            self.ll_queue_event.clear()
        return self.ll_queue.popleft()


class ControllerTest(unittest.IsolatedAsyncioTestCase):
    """Helper class for writing controller tests using the python bindings.
    The test setups the controller sending the Reset command and configuring
    the event masks to allow all events. The local device address is
    always configured as 11:11:11:11:11:11."""

    def setUp(self):
        self.controller = Controller(hci.Address('11:11:11:11:11:11'))

    async def asyncSetUp(self):
        controller = self.controller

        # Start the controller timer.
        await controller.start()

        # Reset the controller and enable all events and LE events.
        controller.send_cmd(hci.Reset())
        await controller.expect_evt(hci.ResetComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))
        controller.send_cmd(hci.SetEventMask(event_mask=0xffffffffffffffff))
        await controller.expect_evt(hci.SetEventMaskComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))
        controller.send_cmd(hci.LeSetEventMask(le_event_mask=0xffffffffffffffff))
        await controller.expect_evt(hci.LeSetEventMaskComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))
        controller.send_cmd(hci.LeReadLocalSupportedFeatures())

        # Load the local supported features to be able to disable tests
        # that rely on unsupported features.
        evt = await self.expect_cmd_complete(hci.LeReadLocalSupportedFeaturesComplete)
        controller.le_features = LeFeatures(evt.le_features)

    async def expect_evt(self, expected_evt: hci.Event, timeout: int = 3):
        packet = await asyncio.wait_for(self.controller.receive_evt(), timeout=timeout)
        evt = hci.Event.parse_all(packet)

        if evt != expected_evt:
            print("received unexpected event")
            print("expected event:")
            expected_evt.show()
            print("received event:")
            evt.show()
            self.assertTrue(False)

    async def expect_cmd_complete(self, expected_evt: type, timeout: int = 3) -> hci.Event:
        packet = await asyncio.wait_for(self.controller.receive_evt(), timeout=timeout)
        evt = hci.Event.parse_all(packet)

        if not isinstance(evt, expected_evt):
            print("received unexpected event")
            print("expected event:")
            print(expected_evt)
            print("received event:")
            evt.show()
            self.assertTrue(False)

        assert evt.status == ErrorCode.SUCCESS
        assert evt.num_hci_command_packets == 1
        return evt

    async def expect_ll(self, expected_pdu: ll.LinkLayerPacket, timeout: int = 3):
        packet = await asyncio.wait_for(self.controller.receive_ll(), timeout=timeout)
        pdu = ll.LinkLayerPacket.parse_all(packet)

        if pdu != expected_pdu:
            print("received unexpected pdu")
            print("expected pdu:")
            expected_pdu.show()
            print("received pdu:")
            pdu.show()
            self.assertTrue(False)

    def tearDown(self):
        self.controller.stop()
