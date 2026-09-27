// Replay a recorded MAX30102 capture through the real PulseDetector, in the standard and the strict gate.
//   record:  pio run -e chk_device -t upload  with  PLATFORMIO_BUILD_FLAGS="-DRIPAR_CHECK_START_PULSE=1 -DRIPAR_CHECK_RAW=1"
//            then save the serial output (lines "raw,<n>,<ir>,<red>", 100 Hz) to a file
//   build:   g++ -std=c++14 -O2 -Iinclude tools/pulse_replay.cpp src/pulse_algo.cpp -o F:/tmp/pulse_replay
//   run:     F:/tmp/pulse_replay capture.txt        (prints the first pass time and a per-second trace per mode)
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "pulse_algo.h"

using namespace ripar;

struct Sample {
  uint32_t ir, red;
};

static void replay(const std::vector<Sample>& v, bool strict) {
  PulseConfig c;
  c.strict = strict;
  PulseDetector d(c);
  uint32_t t = 1000;
  double firstPass = -1;
  uint32_t nextPrint = 0;
  std::printf("== %s gate ==\n", strict ? "STRICT" : "STANDARD");
  for (size_t i = 0; i < v.size(); i++, t += 10) {
    const PulseResult& r = d.add(v[i].ir, v[i].red, t);
    if (r.passed && firstPass < 0) firstPass = r.elapsedMs / 1000.0;
    if (i / 100 >= nextPrint) {
      std::printf("t=%5.1fs finger=%d bpm=%5.1f beats=%2d jitter=%.3f regular=%.2f window=%d passed=%d\n", i / 100.0,
                  r.finger, double(r.bpm), r.beats, double(r.jitter), double(r.regular), r.windowOk, r.passed);
      nextPrint = uint32_t(i / 100) + 1;
    }
  }
  if (firstPass >= 0)
    std::printf("-> PASSED after %.2f s of finger contact\n\n", firstPass);
  else
    std::printf("-> never passed\n\n");
}

int main(int argc, char** argv) {
  if (argc < 2) {
    std::fprintf(stderr, "usage: pulse_replay <capture.txt>\n");
    return 2;
  }
  FILE* f = std::fopen(argv[1], "rb");
  if (!f) {
    std::perror(argv[1]);
    return 2;
  }
  std::vector<Sample> v;
  char line[256];
  while (std::fgets(line, sizeof line, f)) {
    const char* p = std::strstr(line, "raw,");
    if (!p) continue;
    unsigned long n, ir, red;
    if (std::sscanf(p, "raw,%lu,%lu,%lu", &n, &ir, &red) == 3) v.push_back({uint32_t(ir), uint32_t(red)});
  }
  std::fclose(f);
  std::printf("%zu samples (%.1f s at 100 Hz)\n\n", v.size(), v.size() / 100.0);
  replay(v, false);
  replay(v, true);
  return 0;
}
