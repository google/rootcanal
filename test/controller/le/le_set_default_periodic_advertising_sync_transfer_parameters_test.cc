#include <gtest/gtest.h>
#include "model/controller/le_controller.h"

namespace rootcanal {
using namespace bluetooth::hci;

class LeSetDefaultPeriodicAdvertisingSyncTransferParametersTest : public ::testing::Test {
public:
  LeSetDefaultPeriodicAdvertisingSyncTransferParametersTest() = default;
  ~LeSetDefaultPeriodicAdvertisingSyncTransferParametersTest() override = default;

protected:
  Address address_{0};
  ControllerProperties properties_{};
  LeController controller_{address_, properties_};
};

TEST_F(LeSetDefaultPeriodicAdvertisingSyncTransferParametersTest, Success) {
  ASSERT_EQ(controller_.LeSetDefaultPeriodicAdvertisingSyncTransferParameters(
                    SyncTransferMode::SYNC_DISABLED, 0, 0x100, (bluetooth::hci::CteType)0),
            ErrorCode::SUCCESS);
}


}  // namespace rootcanal
