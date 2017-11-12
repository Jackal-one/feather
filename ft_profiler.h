#pragma once
#include <inttypes.h>

// todo: implement block allocator for timelines.
// todo: properly encode timestamps with metadata etc..
// todo: write workbench stress application for test/feature.

const uint32_t k_num_block_bytes = 64u*1024u;
const uint32_t k_max_threads = 64u;
const uint32_t k_max_timeline_bitmasks = k_max_threads / sizeof(uint32_t);

struct ft_profiler_i {
  void (*begin_profile_thread)(const char* name);
  void (*end_profile_thread)();
  void (*put_timestamp)(uint16_t meta, uint32_t timestamp, uint8_t type);
  void (*flush_data)();
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

struct ft_timeline_t {
  uint32_t write_index : 31u;
  uint32_t release_flag : 1u;
};

struct ft_data_block_t {
  std::atomic<uint32_t> num_used;
  uint64_t* data;
};

struct ft_profiler_t {
  uint8_t* mem_arena;
  std::atomic<uint32_t> buffer_write_index;

  uint32_t num_blocks_allocated;
  uint32_t num_blocks_used;
  uint32_t buffer_index;

  ft_timeline_t timeline_pool[k_max_threads];
  uint32_t free_list[k_max_timeline_bitmasks];
  std::mutex flush_lock;
};

const uint32_t k_max_timestamps = (k_num_block_bytes - sizeof(ft_data_block_t)) / sizeof(uint64_t);
const uint32_t k_max_flip = 2u;

thread_local ft_timeline_t* g_tls_timeline = NULL;
static ft_profiler_t* g_profiler = NULL;

bool ft_find_next_free_index(uint32_t& index) {
  for (uint32_t dword_index=0u; dword_index<k_max_timeline_bitmasks; ++dword_index) {
    uint32_t& bitmask = g_profiler->free_list[dword_index];
    if (bitmask > 0u) {
      const uint32_t bit_index = __builtin_clz(bitmask);
      bitmask ^= bit_index + 1u;
      index = bit_index + dword_index * 32u;
      return true;
    }
  }

  return false;
}

void ft_release_index(uint32_t index) {
  const uint32_t dword_index = index / 32u;
  const uint32_t bit_index = index % 32u;
  g_profiler->free_list[dword_index] ^= 1u << bit_index;
}

void ft_request_thread_timeline(const char* name) {
  std::lock_guard<std::mutex> lock(g_profiler->flush_lock);
  uint32_t index = -1;
  ft_find_next_free_index(index);
  g_tls_timeline = &g_profiler->timeline_pool[index];
  g_tls_timeline->write_index = index * k_num_block_bytes;
  g_profiler->num_blocks_used++;
}

void ft_release_thread_timeline() {
  std::lock_guard<std::mutex> lock(g_profiler->flush_lock);
  g_tls_timeline->release_flag = 1u;
  g_tls_timeline = NULL;
}

uint64_t ft_pack_timestamp(uint16_t meta, uint32_t timestamp, uint8_t type) {
  return timestamp;
}

void ft_write_timestamp(ft_timeline_t* timeline, uint64_t token) {
  const uint32_t base_index = g_profiler->buffer_write_index.load(std::memory_order_acquire);
  ft_data_block_t* block = (ft_data_block_t*)&g_profiler->mem_arena[base_index + timeline->write_index];
  const uint32_t next = block->num_used % k_max_timestamps;
  block->data[next] = token;
  block->num_used.fetch_add(1u, std::memory_order_release);
}

void ft_put_timestamp(uint16_t meta, uint32_t timestamp, uint8_t type) {
  ft_timeline_t* timeline = g_tls_timeline;
  if (timeline) {
    ft_write_timestamp(timeline, ft_pack_timestamp(meta, timestamp, type));
  }
}

void ft_flush_data() {
  std::lock_guard<std::mutex> lock(g_profiler->flush_lock);
  const uint32_t buffer_index = g_profiler->buffer_index;
  g_profiler->buffer_index = (g_profiler->buffer_index + 1u) % k_max_flip;

  const size_t num_buffer_bytes = k_num_block_bytes * g_profiler->num_blocks_allocated;
  uint8_t* next_write_buffer = &g_profiler->mem_arena[g_profiler->buffer_index * num_buffer_bytes];
  uint8_t* read_buffer = &g_profiler->mem_arena[buffer_index * num_buffer_bytes];

  for (uint32_t index=0u; index<g_profiler->num_blocks_allocated; ++index) {
    ft_data_block_t* block = (ft_data_block_t*)&next_write_buffer[index * k_num_block_bytes];
    block->num_used = 0u;
  }

  g_profiler->buffer_write_index.store(g_profiler->buffer_index * num_buffer_bytes, std::memory_order_release);

  for (uint32_t index=0u; index<g_profiler->num_blocks_used; ++index) {
    ft_data_block_t* block = (ft_data_block_t*)&read_buffer[index * k_num_block_bytes];
    const uint32_t num_used = block->num_used.load(std::memory_order_acquire);

    const uint32_t start = num_used > k_max_timestamps ? (num_used % k_max_timestamps) : 0u;
    const uint32_t num_ts = num_used > k_max_timestamps ? k_max_timestamps : num_used;

    // debug
    for (uint32_t tid=0u; tid<num_ts; ++tid) {
      printf("ts: %llu\n", block->data[(start+tid) % k_max_timestamps]);
    }
  }

  for (uint32_t i=0u; i<k_max_threads; ++i) {
    ft_timeline_t* timeline = &g_profiler->timeline_pool[i];
    if (timeline->release_flag) {
      ft_release_index(timeline->write_index / k_num_block_bytes);
      timeline->write_index = -1;
      timeline->release_flag = 0u;
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

  memset(g_profiler->free_list, 0xff, sizeof(g_profiler->free_list));
  memset(g_profiler->timeline_pool, 0x0, sizeof(g_profiler->timeline_pool));
  g_profiler->mem_arena = (uint8_t*)malloc(2u*num_blocks*k_num_block_bytes);
  g_profiler->num_blocks_allocated = num_blocks;
  g_profiler->buffer_write_index = 0u;
  g_profiler->num_blocks_used = 0u;
  g_profiler->buffer_index = 0u;

  for (uint32_t index=0u; index<2u*num_blocks*k_num_block_bytes; index+=k_num_block_bytes) {
    ft_data_block_t* block = (ft_data_block_t*)&g_profiler->mem_arena[index];
    block->data = (uint64_t*)(&block->data + 1u);
    block->num_used = 0u;
  }

  return &g_profiler_api;
}

void ft_close_profiler() {
  free(g_profiler->mem_arena);
  g_profiler = NULL;
}

#endif // FT_PROFILER_IMPL