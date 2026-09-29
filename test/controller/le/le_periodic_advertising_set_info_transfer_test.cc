#include <gtest/gtest.h>
#include "model/controller/le_controller.h"

namespace rootcanal {
using namespace bluetooth::hci;

class LePeriodicAdvertisingSetInfoTransferTest : public ::testing::Test {
public:
  LePeriodicAdvertisingSetInfoTransferTest() = default;
  ~LePeriodicAdvertisingSetInfoTransferTest() override = default;

protected:
  Address address_{0};
  ControllerProperties properties_{};
  LeController controller_{address_, properties_};
};

TEST_F(LePeriodicAdvertisingSetInfoTransferTest, InvalidConnectionHandle) {
  ASSERT_EQ(controller_.LePeriodicAdvertisingSetInfoTransfer(0x1234, 0, 0),
            ErrorCode::UNKNOWN_CONNECTION);
}
}  // namespace rootcanal
