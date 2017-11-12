#include "ft_profiler.h"
#include <functional>
#include <thread>

ft_profiler_i* profiler = NULL;

int worker_fnc(void* args) {
  for (uint32_t i=0u; i<1245u; ++i) {
    struct ft_timeline_t* t = (struct ft_timeline_t*)args;
    profiler->put_timestamp(t, 0u, i, 0u);
  }

  return 0;
}

int main() {
  profiler = ft_open_profiler(4u);
  
  struct ft_timeline_t t0 = { .write_index = 0 };
  struct ft_timeline_t t1 = { .write_index = k_num_block_bytes };
  struct ft_timeline_t t2 = { .write_index = 2u*k_num_block_bytes };

  std::thread workers[3u];
  workers[0u] = std::thread([&] { worker_fnc(&t0); });
  workers[1u] = std::thread([&] { worker_fnc(&t1); });
  workers[2u] = std::thread([&] { worker_fnc(&t2); });

  for (uint32_t i=0u; i<3u; ++i) {
    workers[i].join();
  }

  profiler->flush_data();
  printf("done.\n");

  return 0;
}