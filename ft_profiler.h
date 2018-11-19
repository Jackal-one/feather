#pragma once
#include <inttypes.h>

#ifndef FT_PROFILER_ENABLED
# define FT_PROFILER_ENABLED 0 
#endif

const uint32_t k_max_threads = 16u;
const uint32_t k_max_name_len = 32u;

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

struct ft_platform_profiler_t {
  void (*scope_begin)(const char*, uint32_t);
  void (*scope_event)(const char*, uint32_t);
  void (*scope_end)();
};

#if (FT_PROFILER_ENABLED == 0)

#define FT_TOKEN_PASTE(a, b)
#define FT_TOKEN_PASTE_EX(a, b)
#define FT_DEFINE(token, group, name)
#define FT_EVENT_TOK(token)
#define FT_EVENT(group, name)
#define FT_SCOPE_TOK(token)
#define FT_SCOPE(group, name)
#define FT_COUNTER_TOK(token, value)
#define FT_COUNTER(group, name, value)

#define ft_init_profiler(...)
#define ft_init_profiler_ex(...)
#define ft_end_profiler()
#define ft_flush_data(...)
#define ft_data_read(...)
#define ft_read_counter(...) 0

#else // FT_PROFILER_ENABLED

#define FT_TOKEN_PASTE(a, b) a ## b
#define FT_TOKEN_PASTE_EX(a, b) FT_TOKEN_PASTE(a, b)
#define FT_DEFINE(token, group, name) uint64_t ft_token_##token = ft_make_token(group, name)
#define FT_EVENT_TOK(token) ft_scope_event(ft_token_##token)
#define FT_EVENT(group, name) static uint64_t FT_TOKEN_PASTE_EX(s_token, __LINE__) = ft_make_token(group, name); \
  ft_scope_event(FT_TOKEN_PASTE_EX(s_token, __LINE__))
#define FT_SCOPE_TOK(token) ft_scope_t FT_TOKEN_PASTE_EX(scope, __LINE__)(ft_token_##token)
#define FT_SCOPE(group, name) static uint64_t FT_TOKEN_PASTE_EX(s_token, __LINE__) = ft_make_token(group, name); \
  ft_scope_t FT_TOKEN_PASTE_EX(scope, __LINE__)(FT_TOKEN_PASTE_EX(s_token, __LINE__))
#define FT_COUNTER_TOK(token, value) ft_scope_counter(ft_token_##token, value)
#define FT_COUNTER(group, name, value) static uint64_t FT_TOKEN_PASTE_EX(s_token, __LINE__) = ft_make_token(group, name); \
  ft_scope_counter(ft_token_##token, value)

#ifdef __cplusplus
extern "C" {
#endif

extern void ft_init_profiler();
extern void ft_init_profiler_ex(ft_platform_profiler_t* profiler);
extern void ft_end_profiler();

extern void ft_instrument_thread(const char* name);
extern void ft_end_instrument_thread();

extern uint64_t ft_make_token(const char* group, const char* name);
extern void ft_scope_begin(const uint64_t token);
extern void ft_scope_end(const uint64_t token);
extern void ft_scope_event(const uint64_t token);
extern void ft_scope_counter(const uint64_t token, const uint64_t value);

typedef void (*ft_callback)(const ft_profile_data_t* data, void* user_data);
extern void ft_flush_data(ft_callback flush_data, void* user_data);

extern void ft_data_read(const ft_profile_data_t* data, const uint32_t thread_index,
  const uint32_t index, char** name, char** group, uint64_t* ts, uint8_t* type);
extern uint64_t ft_read_counter(const ft_profile_data_t* data, const uint32_t thread_index,
  const uint32_t index);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus

struct ft_thread_scope {
  ft_thread_scope(const char* name) { ft_instrument_thread(name); };
  ~ft_thread_scope() { ft_end_instrument_thread(); }
};

struct ft_scope_t {
  ft_scope_t(const uint64_t t) : token(t) { ft_scope_begin(token); };
  ~ft_scope_t() { ft_scope_end(token); }
  uint64_t token;
};

#endif 

#ifdef FT_PROFILER_IMPL

#ifndef FT_PLATFORM_PROFILER
# define FT_PLATFORM_PROFILER 0
#endif

#include <stdlib.h>
#include <stdio.h>
#include <algorithm>
#include <cassert>
#include <chrono>
#include <thread>
#include <atomic>
#include <mutex>

const uint32_t k_max_tokens = 1024u;
const uint32_t k_max_groups = 32u;

const uint32_t k_num_block_bytes = 64u * 1024u;
const uint32_t k_max_timeline_bitmasks = k_max_threads / sizeof(uint32_t);
const uint32_t k_max_timestamps = k_num_block_bytes / sizeof(uint64_t);

const uint32_t k_bits_type = 2u;
const uint32_t k_bits_meta = 21u;
const uint32_t k_bits_value = 41u;
const uint64_t k_mask_type = (1ull << k_bits_type) - 1u;
const uint64_t k_mask_meta = (1ull << k_bits_meta) - 1u;
const uint64_t k_mask_value = (1ull << k_bits_value) - 1u;

struct ft_token_meta_t {
  char names[k_max_tokens * k_max_name_len];
  char groups[k_max_groups * k_max_name_len];
  char thread_names[k_max_threads * k_max_name_len];
  uint32_t used;
  uint32_t num_groups;
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

  ft_platform_profiler_t* platform_profiler;
  ft_profile_data_t profile_data;

  std::mutex lock;
};

thread_local ft_timeline_t* g_tls_timeline = nullptr;

FT_DEFINE(flush_data_internal, "feather", "ft_flush_data");
FT_DEFINE(flush_data_callback, "feather", "callback");
FT_DEFINE(memory_used, "feather", "memory_used");

uint32_t ft_platform_clz(const uint32_t mask) {
  return __builtin_ctz(mask);
}

uint64_t ft_platform_tick() {
  const auto ts = std::chrono::high_resolution_clock::now();
  return std::chrono::duration_cast<std::chrono::microseconds>(ts.time_since_epoch()).count();
}

void ft_util_meta_strcpy(const uint32_t index, char* dest, const char* name) {
  const uint32_t str_len = std::min<uint32_t>(k_max_name_len, std::strlen(name));
  std::memcpy(&dest[index * k_max_name_len], name, str_len);
  std::memset(&dest[index * k_max_name_len + str_len], '\0', 1u);
}

ft_profiler_t* ft_profiler() {
  static ft_profiler_t profiler_inst;
  return &profiler_inst;
}

uint64_t ft_pack_token(const uint32_t name_index, const uint32_t group_index) {
  return ((group_index & 0x1F) << 16u) | (name_index & 0xFFFF);
}

uint32_t ft_get_token_name(const char* name) {
  for (uint32_t i=0u; i<ft_profiler()->tokens_meta.used; i++) {
    if (std::strcmp(&ft_profiler()->tokens_meta.names[i * k_max_name_len], name) == 0) {
      return i;
    }
  }

  const uint32_t index = ft_profiler()->tokens_meta.used++;
  ft_util_meta_strcpy(index, ft_profiler()->tokens_meta.names, name);
  return index;
}

uint32_t ft_get_token_group(const char* name) {
  for (uint32_t i=0u; i<ft_profiler()->tokens_meta.num_groups; i++) {
    if (std::strcmp(&ft_profiler()->tokens_meta.groups[i * k_max_name_len], name) == 0) {
      return i;
    }
  }

  const uint32_t index = ft_profiler()->tokens_meta.num_groups++;
  ft_util_meta_strcpy(index, ft_profiler()->tokens_meta.groups, name);
  return index;
}

uint64_t ft_make_token(const char* group, const char* name) {
  std::lock_guard<std::mutex> lock(ft_profiler()->lock);
  const uint32_t name_index = ft_get_token_name(name);
  const uint32_t group_index = ft_get_token_group(group);
  return ft_pack_token(name_index, group_index);
}

bool ft_find_next_free_index(uint32_t& index) {
  for (uint32_t dword_index=0u; dword_index<k_max_timeline_bitmasks; ++dword_index) {
    uint32_t& bitmask = ft_profiler()->free_list[dword_index];
    if (bitmask > 0u) {
      const uint32_t bit_index = ft_platform_clz(bitmask);
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

void ft_instrument_thread(const char* name) {
  std::lock_guard<std::mutex> lock(ft_profiler()->lock);
  const size_t thread_hash = std::hash<std::thread::id>{}(std::this_thread::get_id());
  uint32_t tl_index = -1;
  uint32_t free_index = -1;

  if (!ft_find_thread_timeline(thread_hash, tl_index)) {
    if (ft_find_next_free_index(free_index)) {
      g_tls_timeline = &ft_profiler()->timeline_pool[free_index];
      g_tls_timeline->thread_hash = thread_hash;
      ft_util_meta_strcpy(free_index, ft_profiler()->tokens_meta.thread_names, name);
    }
  }
}

void ft_end_instrument_thread() {
  std::lock_guard<std::mutex> lock(ft_profiler()->lock);
  g_tls_timeline->flags_release = 1u;
  g_tls_timeline = nullptr;
}

ft_timeline_t* ft_get_thread_timeline() {
  if (!g_tls_timeline) {
    ft_instrument_thread("unknown");
  }

  return g_tls_timeline;
}

void ft_write_qword(ft_timeline_t* timeline, const uint64_t data) {
  const uint32_t index = timeline->num_used;
  uint64_t* buffer = (uint64_t*)&ft_profiler()->mem_arena[timeline->buffer_address];
  std::memcpy(&buffer[index % k_max_timestamps], &data, sizeof(uint64_t));
  timeline->num_used.fetch_add(1u, std::memory_order_release);
}

void ft_write_qword2(ft_timeline_t* timeline, const uint64_t data0, const uint64_t data1) {
  const uint32_t index = timeline->num_used;
  uint64_t* buffer = (uint64_t*)&ft_profiler()->mem_arena[timeline->buffer_address];
  std::memcpy(&buffer[(index + 0u) % k_max_timestamps], &data0, sizeof(uint64_t));
  std::memcpy(&buffer[(index + 1u) % k_max_timestamps], &data1, sizeof(uint64_t));
  timeline->num_used.fetch_add(2u, std::memory_order_release);
}

uint64_t ft_pack_timestamp(uint32_t meta_index, uint64_t timestamp, uint8_t type) {
  return ((type & k_mask_type) << (k_bits_meta + k_bits_value)) | 
    ((meta_index & k_mask_meta) << k_bits_value) |
    (timestamp & k_mask_value);
}

void ft_put_timestamp(ft_timeline_t* timeline, uint32_t token, uint8_t type) {
  const uint64_t ts = ft_platform_tick();
  const uint64_t data = ft_pack_timestamp(token, ts, type);
  ft_write_qword(timeline, data);
}

bool ft_use_platform_profiler() {
  return !!FT_PLATFORM_PROFILER && ft_profiler()->platform_profiler;
}

void ft_scope_begin(const uint64_t token) {
  if (ft_use_platform_profiler()) {
    const char* name = &ft_profiler()->tokens_meta.names[token * k_max_name_len];
    return ft_profiler()->platform_profiler->scope_begin(name, token);
  }

  ft_put_timestamp(ft_get_thread_timeline(), token, 0u);
}

void ft_scope_end(const uint64_t token) {
  if (ft_use_platform_profiler()) {
    return ft_profiler()->platform_profiler->scope_end();
  }

  ft_put_timestamp(ft_get_thread_timeline(), token, 1u);
}

void ft_scope_event(const uint64_t token) {
  if (ft_use_platform_profiler()) {
    const char* name = &ft_profiler()->tokens_meta.names[token * k_max_name_len];
    return ft_profiler()->platform_profiler->scope_event(name, token);
  }

  ft_put_timestamp(ft_get_thread_timeline(), token, 2u);  
}

void ft_scope_counter(const uint64_t token, const uint64_t value) {
  const uint64_t ts = ft_platform_tick();
  ft_write_qword2(ft_get_thread_timeline(), ft_pack_timestamp(token, ts, 3u), value);
}

void ft_data_read(const ft_profile_data_t* data, const uint32_t thread_index,
  const uint32_t index, char** name, char** group, uint64_t* ts, uint8_t* type) {
  const uint32_t qword_index = (index + data->thread_data[thread_index].start) % k_max_timestamps;
  const uint64_t qword = data->thread_data[thread_index].buffer[qword_index];
  const uint32_t meta = (qword >> k_bits_value) & k_mask_meta;
  const uint32_t name_index = meta & 0xFFFF;
  const uint32_t group_index = (meta >> 16u) & 0x1F;

  *ts = (qword & k_mask_value);
  *type = (qword >> (k_bits_value + k_bits_meta)) & k_mask_type;
  *name = &ft_profiler()->tokens_meta.names[name_index * k_max_name_len];
  *group = &ft_profiler()->tokens_meta.groups[group_index * k_max_name_len];
}

uint64_t ft_read_counter(const ft_profile_data_t* data, const uint32_t thread_index,
  const uint32_t index) {
  const uint32_t qword_index = (index + data->thread_data[thread_index].start) % k_max_timestamps;
  return data->thread_data[thread_index].buffer[qword_index];
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

      const uint32_t k_read_offset = 3u;
      const uint32_t k_num_read = k_max_timestamps - k_read_offset;

      ft_profiler()->profile_data.thread_data[thread_index] = (ft_profile_data_t::ft_thread_data_t) {
        .start = num_used > k_max_timestamps ? ((num_used + k_read_offset) % k_max_timestamps) : 0u,
        .count =  num_used > k_max_timestamps ? k_num_read : num_used,
        .buffer = (uint64_t*)&ft_profiler()->mem_arena[timeline->buffer_address],
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

void ft_init_profiler_ex(ft_platform_profiler_t* platform_profiler) {
  ft_profiler()->mem_arena = (uint8_t*)malloc(k_max_threads * k_num_block_bytes);

  memset(ft_profiler()->free_list, 0xff, sizeof(ft_profiler()->free_list));
  memset(ft_profiler()->timeline_pool, 0x0, sizeof(ft_profiler()->timeline_pool));
  memset(ft_profiler()->mem_arena, 0x0, sizeof(k_max_threads * k_num_block_bytes));

  memset(&ft_profiler()->profile_data, 0x0, sizeof(ft_profiler()->profile_data));
  ft_profiler()->profile_data.thread_names = ft_profiler()->tokens_meta.thread_names;
  ft_profiler()->profile_data.token_names = ft_profiler()->tokens_meta.names;

  for (uint32_t i=0u; i<k_max_threads; i++) {
    ft_profiler()->timeline_pool[i].buffer_address = i * k_num_block_bytes;
  }

  if (platform_profiler) {
    ft_profiler()->platform_profiler = platform_profiler;
    assert(platform_profiler->scope_begin);
    assert(platform_profiler->scope_event);
    assert(platform_profiler->scope_end);
  }
}

void ft_init_profiler() {
  ft_init_profiler_ex(nullptr);
}

void ft_end_profiler() {
  free(ft_profiler()->mem_arena);
}

#endif // FT_PROFILER_IMPL
#endif // FT_PROFILER_ENABLED
