#pragma once
#include <inttypes.h>

// todo: create a "our machinery" api style
// todo: create remove timelines
// todo: properly encode timestamps
// todo: write workbench stress application for test/feature.

const uint32_t k_num_block_bytes = 64u*1024u;

struct ft_timeline_t {
  uint32_t write_index;
};

struct ft_profiler_i {
  void (*put_timestamp)(struct ft_timeline_t* timeline, uint16_t token, uint32_t timestamp, uint8_t type);
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

#include <stdatomic.h>
#include <stdlib.h>
#include <stdio.h>

const uint32_t k_max_timestamps = (k_num_block_bytes - sizeof(atomic_uint)) / sizeof(uint64_t);
const uint32_t k_max_flip = 2u;

struct ft_profiler_t {
  uint8_t* mem_arena;
  atomic_uint buffer_write_index;

  uint32_t num_blocks_allocated;
  uint32_t num_blocks_used;
  uint32_t buffer_index;
};

struct ft_data_block_t {
  atomic_uint num_used;
  uint64_t* data;
};

static struct ft_profiler_t* g_profiler;

uint64_t ft_pack_timestamp(uint16_t token, uint32_t timestamp, uint8_t type) {
  return 77ull;
}

void ft_put_timestamp(struct ft_timeline_t* timeline, uint16_t token, uint32_t timestamp, uint8_t type) {
  const uint32_t base_index = atomic_load_explicit(&g_profiler->buffer_write_index, memory_order_acquire);
  struct ft_data_block_t* block = (struct ft_data_block_t*)&g_profiler->mem_arena[base_index + timeline->write_index];
  const uint32_t next = block->num_used % k_max_timestamps;
  block->data[next] = ft_pack_timestamp(token, timestamp, type);
  atomic_fetch_add_explicit(&block->num_used, 1u, memory_order_release);
}

void ft_flush_data() {
  const uint32_t buffer_index = g_profiler->buffer_index;
  g_profiler->buffer_index = (g_profiler->buffer_index + 1u) % k_max_flip;

  const size_t num_buffer_bytes = k_num_block_bytes * g_profiler->num_blocks_allocated;
  uint8_t* next_write_buffer = &g_profiler->mem_arena[g_profiler->buffer_index * num_buffer_bytes];
  uint8_t* read_buffer = &g_profiler->mem_arena[buffer_index * num_buffer_bytes];

  for (uint32_t index=0u; index<g_profiler->num_blocks_allocated; ++index) {
    struct ft_data_block_t* block = (struct ft_data_block_t*)&next_write_buffer[index * k_num_block_bytes];
    block->num_used = 0u;
  }

  atomic_store_explicit(&g_profiler->buffer_write_index, g_profiler->buffer_index * num_buffer_bytes, memory_order_release);

  for (uint32_t index=0u; index<g_profiler->num_blocks_used; ++index) {
    struct ft_data_block_t* block = (struct ft_data_block_t*)&read_buffer[index * k_num_block_bytes];
    const uint32_t num_used = atomic_load_explicit(&block->num_used, memory_order_acquire);

    // debug
    for (uint32_t tid=0u; tid<num_used; ++tid) {
      printf("ts: %llu\n", block->data[tid]);
    }
  }
}

static struct ft_profiler_i g_profiler_api = {
  .put_timestamp = ft_put_timestamp,
  .flush_data = ft_flush_data
};

struct ft_profiler_i* ft_open_profiler(uint32_t num_blocks) {
  static struct ft_profiler_t profiler_inst;
  g_profiler = &profiler_inst;

  g_profiler->mem_arena = (uint8_t*)malloc(2u*num_blocks*k_num_block_bytes);
  g_profiler->num_blocks_allocated = num_blocks;
  g_profiler->buffer_write_index = 0u;
  g_profiler->num_blocks_used = 3u;
  g_profiler->buffer_index = 0u;

  for (uint32_t index=0u; index<2u*num_blocks*k_num_block_bytes; index+=k_num_block_bytes) {
    struct ft_data_block_t* block = (struct ft_data_block_t*)&g_profiler->mem_arena[index];
    block->data = (uint64_t*)&g_profiler->mem_arena[index] + sizeof(block->num_used);
    block->num_used = 0u;
  }

  return &g_profiler_api;
}

void ft_close_profiler() {
  free(g_profiler->mem_arena);
  g_profiler = NULL;
}

#endif // FT_PROFILER_IMPL