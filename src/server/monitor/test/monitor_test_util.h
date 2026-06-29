#ifndef MONITOR_TEST_UTIL_H
#define MONITOR_TEST_UTIL_H

/*
 * monitor_test_util.h — helpers compartidos para tests del módulo monitor.
 *
 *   mt_feed / mt_drain_all  — alimentar bytes y leer respuestas de wb
 *   mt_auth_admin           — AUTH admin admin en una línea
 *   mt_sim_session          — simula ciclo SOCKS en el store
 *   mt_collect_name / mt_collect_log — callbacks para foreach en tests
 */

#include <check.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "monitor_commands.h"
#include "store.h"

#define MT_DRAIN_SIZE 8192

static inline void mt_drain_all(struct monitor_commands_session *proto, char *out, size_t out_len)
{
    out[0] = '\0';
    uint8_t buf[512];

    while (buffer_can_read(&proto->wb))
    {
        const size_t n = monitor_commands_wb_read(proto, buf, sizeof(buf));
        if (n == 0)
        {
            break;
        }
        buf[n] = '\0';
        strncat(out, (const char *)buf, out_len - strlen(out) - 1);
    }
}

static inline void mt_feed(struct monitor_commands_session *proto, const char *text)
{
    monitor_commands_feed(proto, (const uint8_t *)text, strlen(text));
}

static inline void mt_auth_admin(struct monitor_commands_session *proto)
{
    mt_feed(proto, "AUTH admin admin\n");
}

static inline void mt_assert_has(const char *haystack, const char *needle)
{
    ck_assert_ptr_nonnull(strstr(haystack, needle));
}

static inline store_session_id mt_sim_session(struct monitor_store *store,
                                              const char *user,
                                              const char *host,
                                              uint16_t port,
                                              uint64_t up,
                                              uint64_t down,
                                              bool end_session)
{
    const store_session_id id = store_session_begin(store);
    ck_assert(id != STORE_SESSION_INVALID);
    store_session_set_user(store, id, user);
    store_session_set_phase(store, id, STORE_SESSION_CONNECTING);
    store_session_set_dest(store, id, host, port);
    if (up > 0 || down > 0)
    {
        store_session_add_bytes(store, id, up, down);
    }
    if (end_session)
    {
        store_session_end(store, id);
    }
    return id;
}

typedef struct
{
    size_t count;
    char names[16][STORE_MAX_USERNAME + 1];
} mt_name_list;

static inline bool mt_collect_name(const char *username, void *ctx)
{
    mt_name_list *list = ctx;

    if (list->count < 16)
    {
        strncpy(list->names[list->count], username, STORE_MAX_USERNAME);
        list->names[list->count][STORE_MAX_USERNAME] = '\0';
        list->count++;
    }
    return true;
}

typedef struct
{
    size_t count;
    store_log_id ids[16];
    char hosts[16][STORE_MAX_DEST_HOST + 1];
} mt_log_list;

static inline bool mt_collect_log(const store_log_entry *entry, void *ctx)
{
    mt_log_list *list = ctx;

    if (list->count < 16)
    {
        list->ids[list->count] = entry->id;
        strncpy(list->hosts[list->count], entry->host, STORE_MAX_DEST_HOST);
        list->hosts[list->count][STORE_MAX_DEST_HOST] = '\0';
        list->count++;
    }
    return true;
}

#endif
