#pragma once
#include <inttypes.h>

// todo: implement block allocator for timelines.
// todo: properly encode timestamps with metadata etc..
// todo: write workbench stress application for test/feature.

struct ft_thread_data_t {
  uint64_t* buffer;
  uint32_t start;
  uint32_t count;
};

typedef void (*ft_callback)(const ft_thread_data_t* data);

struct ft_profiler_i {
  void (*begin_profile_thread)(const char* name);
  void (*end_profile_thread)();
  void (*put_timestamp)(uint16_t meta, uint32_t timestamp, uint8_t type);
  void (*flush_data)(ft_callback);
};

#ifdef __cplusplus
extern "C" {
#endif

extern struct ft_profiler_i* ft_open_profiler(uint32_t num_blocks);
extern void ft_close_profiler();

#ifdef __cplusplus
}
#endif

#ifdef FT_PROFILER_IMPL

#include <stdlib.h>
#include <stdio.h>
#include <atomic>
#include <mutex>

const uint32_t k_num_block_bytes = 64u * 1024u;
const uint32_t k_max_threads = 64u;
const uint32_t k_max_timeline_bitmasks = k_max_threads / sizeof(uint32_t);
const uint32_t k_max_timestamps = k_num_block_bytes / sizeof(uint64_t);

struct ft_timeline_t {
  std::atomic<uint32_t> num_used;
  uint32_t buffer_address;
  uint8_t flags_release : 1u;
};

struct ft_profiler_t {
  uint8_t* mem_arena;

  uint32_t num_blocks_allocated;
  uint32_t num_blocks_used;

  ft_timeline_t timeline_pool[k_max_threads];
  uint32_t free_list[k_max_timeline_bitmasks];
  std::mutex flush_lock;
};

thread_local ft_timeline_t* g_tls_timeline = nullptr;
static ft_profiler_t* g_profiler = nullptr;

uint32_t platform_clz(const uint32_t mask) {
  return __builtin_ctz(mask);
}

bool ft_find_next_free_index(uint32_t& index) {
  for (uint32_t dword_index=0u; dword_index<k_max_timeline_bitmasks; ++dword_index) {
    uint32_t& bitmask = g_profiler->free_list[dword_index];
    if (bitmask > 0u) {
      const uint32_t bit_index = platform_clz(bitmask);
      bitmask ^= 1u << bit_index;
      index = bit_index + dword_index * 32u;
      return true;
    }
  }

  return false;
}

void ft_release_index(const uint32_t index) {
  const uint32_t dword_index = index / 32u;
  const uint32_t bit_index = index % 32u;
  g_profiler->free_list[dword_index] ^= 1u << bit_index;
}

void ft_request_thread_timeline(const char* name) {
  std::lock_guard<std::mutex> lock(g_profiler->flush_lock);
  uint32_t index = -1;
  if (ft_find_next_free_index(index)) {
    g_tls_timeline = &g_profiler->timeline_pool[index];
    g_tls_timeline->buffer_address = index * k_num_block_bytes;
    g_profiler->num_blocks_used++;
  }
}

void ft_release_thread_timeline() {
  std::lock_guard<std::mutex> lock(g_profiler->flush_lock);
  g_tls_timeline->flags_release = 1u;
  g_tls_timeline = nullptr;
}

uint64_t ft_pack_timestamp(uint16_t meta, uint32_t timestamp, uint8_t type) {
  return timestamp;
}

void ft_write_qword(ft_timeline_t* timeline, uint64_t token) {
  const uint32_t next = timeline->num_used % k_max_timestamps;
  uint64_t* buffer = (uint64_t*)&g_profiler->mem_arena[timeline->buffer_address];
  std::memcpy(&buffer[next], &token, sizeof(uint64_t));
  timeline->num_used.fetch_add(1u, std::memory_order_release);
}

void ft_put_timestamp(uint16_t meta, uint32_t timestamp, uint8_t type) {
  ft_timeline_t* timeline = g_tls_timeline;
  ft_write_qword(timeline, ft_pack_timestamp(meta, timestamp, type));
}

void ft_flush_data(ft_callback flush_data) {
  std::lock_guard<std::mutex> lock(g_profiler->flush_lock);

  for (uint32_t i=0u; i<g_profiler->num_blocks_used; ++i) {
    const ft_timeline_t* timeline = &g_profiler->timeline_pool[i];
    const uint32_t num_used = timeline->num_used.load(std::memory_order_acquire);

    ft_thread_data_t td = {
      .buffer = (uint64_t*)&g_profiler->mem_arena[timeline->buffer_address],
      .start = num_used > k_max_timestamps ? (num_used % k_max_timestamps) : 0u,
      .count =  num_used > k_max_timestamps ? k_max_timestamps : num_used,
    };

    flush_data(&td);
  }

  for (uint32_t i=0u; i<k_max_threads; ++i) {
    ft_timeline_t* timeline = &g_profiler->timeline_pool[i];
    if (timeline->flags_release) {
      ft_release_index(timeline->buffer_address / k_num_block_bytes);
      timeline->buffer_address = -1;
      timeline->flags_release = 0u;
      g_profiler->num_blocks_used--;
    }
  }
}

static struct ft_profiler_i g_profiler_api = {
  .begin_profile_thread = ft_request_thread_timeline,
  .end_profile_thread = ft_release_thread_timeline,
  .put_timestamp = ft_put_timestamp,
  .flush_data = ft_flush_data
};

ft_profiler_i* ft_open_profiler(uint32_t num_blocks) {
  static ft_profiler_t profiler_inst;
  g_profiler = &profiler_inst;

  g_profiler->mem_arena = (uint8_t*)malloc(num_blocks * k_num_block_bytes);
  g_profiler->num_blocks_allocated = num_blocks;
  g_profiler->num_blocks_used = 0u;

  memset(g_profiler->free_list, 0xff, sizeof(g_profiler->free_list));
  memset(g_profiler->timeline_pool, 0x0, sizeof(g_profiler->timeline_pool));
  memset(g_profiler->mem_arena, 0x0, sizeof(num_blocks * k_num_block_bytes));

  for (uint32_t i=0u; i<k_max_threads; i++) {
    g_profiler->timeline_pool[i].buffer_address = i * k_num_block_bytes;
  }

  return &g_profiler_api;
}

void ft_close_profiler() {
  free(g_profiler->mem_arena);
  g_profiler = nullptr;
}

#endif // FT_PROFILER_IMPL
