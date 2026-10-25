#pragma once
// Only owner-confirmed hardware facts carried into this independent project.
namespace board {
constexpr int up = 8, down = 13, left = 5, right = 9, select = 4;
constexpr int sclk = 2, mosi = 3, miso = -1, cs = 7, dc = 6, reset = 10;
constexpr int batteryAdc = 0; // Not sampled: divider/calibration not confirmed.
constexpr unsigned spiHz = 24000000;
constexpr int rotation = 3;
} // namespace board
