#include "ft_profiler.h"
#include <thread>

int worker_fnc(void* args) {
  for (uint32_t i=0u; i<32u; ++i) {
    printf(".");
  }

  printf("\n done.\n");
  return 0;
}

int main() {

  ft_profiler_i* profiler = ft_open_profiler(4u);
  
  struct ft_timeline_t t0 = { .write_index = 0 };
  struct ft_timeline_t t1 = { .write_index = k_num_block_bytes };
  struct ft_timeline_t t2 = { .write_index = 2u*k_num_block_bytes };

  profiler->put_timestamp(&t0, 0u, 44234234u, 0u);
  profiler->put_timestamp(&t1, 0u, 64346356u, 0u);
  profiler->put_timestamp(&t2, 0u, 23454359u, 0u);

  profiler->flush_data();

/*
  int32_t res;
  thrd_t worker;
  thrd_create(&worker, worker_fnc, NULL);
  thrd_join(&worker_fnc, &res);
*/

  return 0;
}