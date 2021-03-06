#define FT_PROFILER_IMPL
#include "ft_profiler.h"

#include <functional>
#include <iostream>
#include <thread>
#include <fstream>
#include <algorithm>
#include <vector>
#include <unistd.h>

// todo(mgiacal):s
// - test constexpr thread safety.

FT_DEFINE(main_loop, "app", "main_loop", FT_TIMER);
FT_DEFINE(json_write, "app", "json_write", FT_TIMER);

int worker_fnc(void* args) {
  char name[64];
  sprintf(name, "worker_%zu", (size_t)args);
  ft_thread_scope tt(name);

  // for (uint32_t i=0u; i<1024u; ++i) {
  uint32_t i = 0u;
  while (1) {
    {
      FT_SCOPE("rendering", "job");
      usleep((rand() % 10000));
    }
    {
      FT_SCOPE("rendering", "job2");
      usleep((rand() % 10000));
    }
  }

  return 0;
}

void flush_data(const ft_profile_data_t* data, void* user_data) {
  for (uint32_t tid=0u; tid<data->num_threads; tid++) {
    const char* thread_name = &data->thread_names[tid * k_max_name_len];
    const ft_profile_data_t::ft_thread_data_t* thread_data = &data->thread_data[tid];
    const uint32_t count = thread_data->count;
  
    for (uint32_t i=0u; i<count; i++) {
      char* name; uint64_t ts; uint8_t type;
      ft_data_read(data, tid, i, &name, &ts, &type);
      printf("thread: %s, tid: %d, name: %s, event: %d, time: %llu\n", thread_name, tid, name, type, ts);
    }
  }
}

void json_trace_save_to_file(const ft_profile_data_t* data, void* user_data) {
  const char* path = (const char*)user_data;
  std::ofstream output_file(path, std::ofstream::out | std::ofstream::binary);
  if (output_file.is_open())
  {
    FT_SCOPE_TOK(json_write);
    output_file << "[ " << std::endl;

    for (uint32_t tid=0u; tid<data->num_threads; tid++) {
      const ft_profile_data_t::ft_thread_data_t* thread_data = &data->thread_data[tid];
      const uint32_t count = thread_data->count;
    
      for (uint32_t i=0u; i<count; i++) {
        char* name; uint64_t ts; uint8_t type;
        ft_data_read(data, tid, i, &name, &ts, &type);

        output_file << "\t{ ";
        output_file << "\"name\": \"" << name << "\", ";
        output_file << "\"cat\": \"" << "cat" << "\", ";
        output_file << "\"ph\": \"" << (type ? "E" : "B") << "\", ";
        output_file << "\"pid\": " << 0u << ", ";
        output_file << "\"tid\": " << tid << ", ";
        output_file << "\"ts\": " << ts << " }," << std::endl;
      }
    }

    for (uint32_t tid=0u; tid<data->num_threads; tid++) {
      const char* thread_name = &data->thread_names[tid * k_max_name_len];
      const bool is_last_item = (tid == (data->num_threads - 1u));

      output_file << "\t{ \"name\": \"thread_name\", \"ph\": \"M\", ";
      output_file << "\"pid\": " << 0u << ", ";
      output_file << "\"tid\": " << tid << ", ";
      output_file << "\"args\": { \"name\" : \"" << thread_name <<  "\"}";
      output_file << (is_last_item ? " }" : " },") << std::endl;
    }

    output_file << " ]" << std::endl;

    output_file.close();
  }
}

int main() {
  ft_init_profiler(5u);
  ft_instrument_thread("main");
  
  const uint32_t k_max_threads = 4u;
  std::thread workers[k_max_threads];
  for (uint32_t i=0u; i<k_max_threads; ++i) {
    workers[i] = std::thread([=] { worker_fnc((void*)i); });
  }

  while (1) {
    {
    FT_SCOPE_TOK(main_loop);
    usleep(500000);}
    ft_flush_data(json_trace_save_to_file, (void*)"trace.json");
  }

  for (uint32_t i=0u; i<k_max_threads; ++i) {
    workers[i].join();
  }

  ft_end_profiler();

  printf("done.\n");
  return 0;
}
