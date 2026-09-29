#include <gtest/gtest.h>
#include "model/controller/le_controller.h"

namespace rootcanal {
using namespace bluetooth::hci;

class LePeriodicAdvertisingSyncTransferTest : public ::testing::Test {
public:
  LePeriodicAdvertisingSyncTransferTest() = default;
  ~LePeriodicAdvertisingSyncTransferTest() override = default;

protected:
  Address address_{0};
  ControllerProperties properties_{};
  LeController controller_{address_, properties_};
};

TEST_F(LePeriodicAdvertisingSyncTransferTest, InvalidConnectionHandle) {
  ASSERT_EQ(controller_.LePeriodicAdvertisingSyncTransfer(0x1234, 0, 0),
            ErrorCode::UNKNOWN_CONNECTION);
}
}  // namespace rootcanal
