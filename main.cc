#define FT_PROFILER_IMPL
#include "ft_profiler.h"
#include <functional>
#include <thread>

ft_profiler_i* profiler = nullptr;

int worker_fnc(void* args) {
  profiler->begin_profile_thread("worker");
  for (uint32_t i=0u; i<1024u; ++i) {
    profiler->put_timestamp(0u, i, 0u);
  }
  profiler->end_profile_thread();
  return 0;
}

int main() {
  profiler = ft_open_profiler(4u);
  
  const uint32_t k_max_threads = 4u;
  std::thread workers[k_max_threads];
  for (uint32_t i=0u; i<k_max_threads; ++i) {
    workers[i] = std::thread([] { worker_fnc(nullptr); });
  }

  for (uint32_t i=0u; i<k_max_threads; ++i) {
    workers[i].join();
  }

  profiler->flush_data();
  ft_close_profiler();

  printf("done.\n");
  return 0;
}
