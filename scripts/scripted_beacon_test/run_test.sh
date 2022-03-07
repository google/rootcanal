
mkdir -p /tmp/logs/scripted_beacon_test/
chmod 200 scripts/scripted_beacon_test/no_permission.pb
chmod 200 scripts/scripted_beacon_test/grant_permission.pb
# ls -l scripts/scripted_beacon_test/*.pb
$ANDROID_BUILD_TOP/out/host/linux-x86/bin/root-canal 2> /tmp/logs/scripted_beacon_test/root_canal.log &
sleep 1
python3 scripts/test_channel.py 6401 < scripts/scripted_beacon_test/add_beacons > /tmp/logs/scripted_beacon_test/test_channel.log &
python3 scripts/hci_socket.py 6402 < scripts/scripted_beacon_test/start_scan > /tmp/logs/scripted_beacon_test/hci_device.log &
sleep 5
chmod 640 scripts/scripted_beacon_test/grant_permission.pb
# ls -l scripts/scripted_beacon_test/*.pb
sleep 15
echo "Done"
chmod 640 scripts/scripted_beacon_test/no_permission.pb
# ls -l scripts/scripted_beacon_test/*.pb
gqui /tmp/logs/scripted_beacon_test/*.pb
