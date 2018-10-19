#pragma once
#include <inttypes.h>

// todo(mgiacal):
// - redesign api?
// - support counters.
// - write workbench stress application for test/feature.

const uint32_t k_max_name_len = 32u;
const uint32_t k_max_tokens = 1024u;
const uint32_t k_max_threads = 16u;

#define FT_TIMER 0u
#define FT_EVENT 1u
#define FT_COUNTER 2u

#define FT_TOKEN_PASTE(a, b) a ## b
#define FT_TOKEN_PASTE_EX(a, b) FT_TOKEN_PASTE(a, b)
#define FT_DEFINE(token, group, name, event) uint64_t ft_token_##token = ft_make_token(group, name)
#define FT_SCOPE_TOK(token) ft_scope_t FT_TOKEN_PASTE_EX(scope, __LINE__)(ft_token_##token)
#define FT_SCOPE(group, name) static uint64_t FT_TOKEN_PASTE_EX(s_token, __LINE__) = ft_make_token(group, name); \
  ft_scope_t FT_TOKEN_PASTE_EX(scope, __LINE__)(FT_TOKEN_PASTE_EX(s_token, __LINE__))

struct ft_profile_data_t {
  struct ft_thread_data_t {
    uint32_t start;
    uint32_t count;
    uint64_t* buffer;
  };

  ft_thread_data_t thread_data[k_max_threads];
  const char* token_names;
  const char* thread_names;
  uint32_t num_threads;
};

typedef void (*ft_callback)(const ft_profile_data_t* data, void* user_data);

struct ft_profiler_i {
  void (*begin_profile_thread)(const char* name);
  void (*end_profile_thread)();
  void (*flush_data)(ft_callback, void* user_data);
};

#ifdef __cplusplus
extern "C" {
#endif

extern uint64_t ft_make_token(const char* group, const char* name);
extern void ft_scope_begin(const uint64_t token);
extern void ft_scope_end(const uint64_t token);

extern void ft_data_read(const ft_profile_data_t* data, const uint32_t thread_index,
  const uint32_t index, char** name, uint64_t* ts, uint8_t* type);

extern struct ft_profiler_i* ft_open_profiler(uint32_t num_blocks);
extern void ft_close_profiler();

#ifdef __cplusplus
struct ft_scope_t {
  ft_scope_t(const uint64_t t) : token(t) { ft_scope_begin(token); };
  ~ft_scope_t() { ft_scope_end(token); }
  uint64_t token;
};
#endif 

#ifdef __cplusplus
}
#endif

#ifdef FT_PROFILER_IMPL

#include <stdlib.h>
#include <stdio.h>
#include <cassert>
#include <chrono>
#include <thread>
#include <atomic>
#include <mutex>

const uint32_t k_num_block_bytes = 32u * 1024u;
const uint32_t k_max_timeline_bitmasks = k_max_threads / sizeof(uint32_t);
const uint32_t k_max_timestamps = k_num_block_bytes / sizeof(uint64_t);

const uint32_t k_bits_type = 2u;
const uint32_t k_bits_meta = 16u;
const uint32_t k_bits_value = 46;
const uint64_t k_mask_type = (1ull << k_bits_type) - 1u;
const uint64_t k_mask_meta = (1ull << k_bits_meta) - 1u;
const uint64_t k_mask_value = (1ull << k_bits_value) - 1u;

struct ft_token_meta_t {
  char names[k_max_tokens * k_max_name_len];
  char thread_names[k_max_threads * k_max_name_len];
  uint32_t used;
};

struct ft_timeline_t {
  std::atomic<uint32_t> num_used;
  uint32_t buffer_address;
  size_t thread_hash;
  uint8_t flags_release : 1u;
};

struct ft_profiler_t {
  uint8_t* mem_arena;

  ft_token_meta_t tokens_meta;
  ft_timeline_t timeline_pool[k_max_threads];
  uint32_t free_list[k_max_timeline_bitmasks];

  ft_profile_data_t profile_data;
  std::mutex lock;
};

thread_local ft_timeline_t* g_tls_timeline = nullptr;

FT_DEFINE(flush_data_internal, "feather", "ft_flush_data", FT_TIMER);
FT_DEFINE(flush_data_callback, "feather", "callback", FT_TIMER);
FT_DEFINE(flush_data_event, "feather", "ft_flush_data", FT_EVENT);
FT_DEFINE(memory_used, "feather", "memory_used", FT_EVENT);

uint32_t platform_clz(const uint32_t mask) {
  return __builtin_ctz(mask);
}

uint64_t platform_tick() {
  const auto ts = std::chrono::high_resolution_clock::now();
  return std::chrono::duration_cast<std::chrono::microseconds>(ts.time_since_epoch()).count();
}

uint64_t ft_pack_token(const uint32_t token_index) {
  return token_index;
}

void ft_util_meta_strcpy(const uint32_t index, char* dest, const char* name) {
  const size_t str_len = std::strlen(name);
  std::memcpy(&dest[index * k_max_name_len], name, str_len);
  std::memset(&dest[index * k_max_name_len + str_len], '\0', 1u);
}

ft_profiler_t* ft_profiler() {
  static ft_profiler_t profiler_inst;
  return &profiler_inst;
}

bool ft_find_token(uint64_t& token, const char* group, const char* name) {
  for (uint32_t i=0u; i<ft_profiler()->tokens_meta.used; i++) {
    if (std::strcmp(&ft_profiler()->tokens_meta.names[i * k_max_name_len], name) == 0) {
      token = ft_pack_token(i);
      return true;
    }
  }

  return false;
}

uint64_t ft_push_token(const char* group, const char* name) {
  const uint32_t index = ft_profiler()->tokens_meta.used++;
  ft_util_meta_strcpy(index, ft_profiler()->tokens_meta.names, name);
  return ft_pack_token(index);
}

uint64_t ft_make_token(const char* group, const char* name) {
  std::lock_guard<std::mutex> lock(ft_profiler()->lock);
  uint64_t token = 0u;
  if (!ft_find_token(token, group, name)) {
    token = ft_push_token(group, name);
  }

  return token;
}

bool ft_find_next_free_index(uint32_t& index) {
  for (uint32_t dword_index=0u; dword_index<k_max_timeline_bitmasks; ++dword_index) {
    uint32_t& bitmask = ft_profiler()->free_list[dword_index];
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
  ft_profiler()->free_list[dword_index] ^= 1u << bit_index;
}

void ft_reset_timeline(const uint32_t index) {
  ft_timeline_t* tl = &ft_profiler()->timeline_pool[index];
  tl->num_used = 0u;
  tl->thread_hash = 0u;
  tl->flags_release = 0u;
}

bool ft_find_thread_timeline(const uint64_t thread_hash, uint32_t& index) {
  for (uint32_t i=0u; i<k_max_threads; i++) {
    if (ft_profiler()->timeline_pool[i].thread_hash == thread_hash) {
      index = i; 
      return true;
    }
  }
  
  return false;
}

void ft_request_thread_timeline(const char* name) {
  std::lock_guard<std::mutex> lock(ft_profiler()->lock);
  const size_t thread_hash = std::hash<std::thread::id>{}(std::this_thread::get_id());
  uint32_t tl_index = -1;
  uint32_t free_index = -1;

  if (!ft_find_thread_timeline(thread_hash, tl_index)) {
    if (ft_find_next_free_index(free_index)) {
      g_tls_timeline = &ft_profiler()->timeline_pool[free_index];
      g_tls_timeline->thread_hash = thread_hash;
      ft_util_meta_strcpy(free_index, ft_profiler()->tokens_meta.thread_names, name ? name : "unknown");
    }
  }
}

void ft_release_thread_timeline() {
  std::lock_guard<std::mutex> lock(ft_profiler()->lock);
  g_tls_timeline->flags_release = 1u;
  g_tls_timeline = nullptr;
}

ft_timeline_t* ft_get_thread_timeline() {
  if (!g_tls_timeline) {
    ft_request_thread_timeline("unknown");
  }

  return g_tls_timeline;
}

uint64_t ft_pack_timestamp(uint32_t meta_index, uint64_t timestamp, uint8_t type) {
  return ((type & k_mask_type) << (k_bits_meta + k_bits_value)) | 
    ((meta_index & k_mask_meta) << k_bits_value) |
    (timestamp & k_mask_value);
}

void ft_write_qword(ft_timeline_t* timeline, uint64_t data) {
  const uint32_t next = timeline->num_used % k_max_timestamps;
  uint64_t* buffer = (uint64_t*)&ft_profiler()->mem_arena[timeline->buffer_address];
  std::memcpy(&buffer[next], &data, sizeof(uint64_t));
  timeline->num_used.fetch_add(1u, std::memory_order_release);
}

void ft_put_timestamp(uint32_t meta_index, uint8_t type) {
  ft_timeline_t* timeline = ft_get_thread_timeline();
  const uint64_t ts = platform_tick();
  ft_write_qword(timeline, ft_pack_timestamp(meta_index, ts, type));
}

void ft_scope_begin(const uint64_t token) {
  ft_put_timestamp(token, 0u);
}

void ft_scope_end(const uint64_t token) {
  ft_put_timestamp(token, 1u);
}

void ft_data_read(const ft_profile_data_t* data, const uint32_t thread_index,
  const uint32_t index, char** name, uint64_t* ts, uint8_t* type) {
  const uint32_t qword_index = (index + data->thread_data[thread_index].start) % k_max_timestamps;
  const uint64_t qword = data->thread_data[thread_index].buffer[qword_index];
  const uint32_t meta_index = (qword >> k_bits_value) & k_mask_meta;

  *ts = (qword & k_mask_value);
  *type = (qword >> (k_bits_value + k_bits_meta)) & k_mask_type;
  *name = &ft_profiler()->tokens_meta.names[meta_index * k_max_name_len];
}

void ft_flush_data(ft_callback flush_data, void* user_data) {
  FT_SCOPE_TOK(flush_data_internal);
  std::lock_guard<std::mutex> lock(ft_profiler()->lock);
  ft_profiler()->profile_data.num_threads = 0u;

  for (uint32_t i=0u; i<k_max_threads; ++i) {
    const ft_timeline_t* timeline = &ft_profiler()->timeline_pool[i];

    if (timeline->thread_hash > 0u) {
      const uint32_t num_used = timeline->num_used.load(std::memory_order_acquire);
      const uint32_t thread_index = ft_profiler()->profile_data.num_threads++;

      const uint32_t k_read_offset = k_max_timestamps / 5u;
      const uint32_t k_num_read = k_max_timestamps - k_read_offset;

      ft_profiler()->profile_data.thread_data[thread_index] = (ft_profile_data_t::ft_thread_data_t) {
        .buffer = (uint64_t*)&ft_profiler()->mem_arena[timeline->buffer_address],
        .start = num_used > k_max_timestamps ? ((num_used + k_read_offset) % k_max_timestamps) : 0u,
        .count =  num_used > k_max_timestamps ? k_num_read : num_used,
      };
    }
  }

  {
    FT_SCOPE_TOK(flush_data_callback);
    flush_data(&ft_profiler()->profile_data, user_data);
  }

  for (uint32_t i=0u; i<k_max_threads; ++i) {
    ft_timeline_t* timeline = &ft_profiler()->timeline_pool[i];
    if (timeline->flags_release) {
      ft_release_index(i);
      ft_reset_timeline(i);
    }
  }
}

static struct ft_profiler_i g_profiler_api = {
  .begin_profile_thread = ft_request_thread_timeline,
  .end_profile_thread = ft_release_thread_timeline,
  .flush_data = ft_flush_data
};

ft_profiler_i* ft_open_profiler(uint32_t num_blocks) {
  ft_profiler()->mem_arena = (uint8_t*)malloc(num_blocks * k_num_block_bytes);

  memset(ft_profiler()->free_list, 0xff, sizeof(ft_profiler()->free_list));
  memset(ft_profiler()->timeline_pool, 0x0, sizeof(ft_profiler()->timeline_pool));
  memset(ft_profiler()->mem_arena, 0x0, sizeof(num_blocks * k_num_block_bytes));

  memset(&ft_profiler()->profile_data, 0x0, sizeof(ft_profiler()->profile_data));
  ft_profiler()->profile_data.thread_names = ft_profiler()->tokens_meta.thread_names;
  ft_profiler()->profile_data.token_names = ft_profiler()->tokens_meta.names;

  for (uint32_t i=0u; i<k_max_threads; i++) {
    ft_profiler()->timeline_pool[i].buffer_address = i * k_num_block_bytes;
  } 

  return &g_profiler_api;
}

void ft_close_profiler() {
  free(ft_profiler()->mem_arena);
}

#endif // FT_PROFILER_IMPL
