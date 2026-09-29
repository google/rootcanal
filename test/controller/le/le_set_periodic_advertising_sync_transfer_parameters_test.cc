#include <gtest/gtest.h>
#include "model/controller/le_controller.h"

namespace rootcanal {
using namespace bluetooth::hci;

class LeSetPeriodicAdvertisingSyncTransferParametersTest : public ::testing::Test {
public:
  LeSetPeriodicAdvertisingSyncTransferParametersTest() = default;
  ~LeSetPeriodicAdvertisingSyncTransferParametersTest() override = default;

protected:
  Address address_{0};
  ControllerProperties properties_{};
  LeController controller_{address_, properties_};
};

TEST_F(LeSetPeriodicAdvertisingSyncTransferParametersTest, InvalidConnectionHandle) {
  ASSERT_EQ(controller_.LeSetPeriodicAdvertisingSyncTransferParameters(
                    0x1234, SyncTransferMode::SYNC_DISABLED, 0, 0x100, (bluetooth::hci::CteType)0),
            ErrorCode::UNKNOWN_CONNECTION);
}
}  // namespace rootcanal
