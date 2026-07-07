/**
 * selector.c - un muliplexor de entrada salida
 */
#include <assert.h> // :)
#include <errno.h>  // :)
#include <pthread.h>
#include <stdio.h>  // perror
#include <stdlib.h> // malloc
#include <string.h> // memset

#include "selector.h"
#include <fcntl.h>
#include <stdint.h> // SIZE_MAX
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define N(x) (sizeof(x) / sizeof((x)[0]))

#define ERROR_DEFAULT_MSG "something failed"

/** retorna una descripción humana del fallo */
const char *selector_error(const selector_status status)
{
    const char *msg;
    switch (status)
    {
    case SELECTOR_SUCCESS:
        msg = "Success";
        break;
    case SELECTOR_ENOMEM:
        msg = "Not enough memory";
        break;
    case SELECTOR_MAXFD:
        msg = "Can't handle any more file descriptors";
        break;
    case SELECTOR_IARGS:
        msg = "Illegal argument";
        break;
    case SELECTOR_IO:
        msg = "I/O error";
        break;
    default:
        msg = ERROR_DEFAULT_MSG;
    }
    return msg;
}

struct selector_init conf;

selector_status selector_init(const struct selector_init *c)
{
    memcpy(&conf, c, sizeof(conf));
    return SELECTOR_SUCCESS;
}

selector_status selector_close(void)
{
    return SELECTOR_SUCCESS;
}

// estructuras internas
struct item
{
    int fd;
    fd_interest interest;
    const fd_handler *handler;
    void *data;
};

/* tarea bloqueante */
struct blocking_job
{
    /** selector dueño de la resolucion */
    fd_selector s;
    /** file descriptor dueño de la resolucion */
    int fd;

    /** datos del trabajo provisto por el usuario */
    void *data;

    /** el siguiente en la lista */
    struct blocking_job *next;
};

/** marca para usar en item->fd para saber que no está en uso */
static const int FD_UNUSED = -1;

/** verifica si el item está usado */
#define ITEM_USED(i) ((FD_UNUSED != (i)->fd))

struct fdselector
{
    // almacenamos en una jump table donde la entrada es el file descriptor.
    // Asumimos que el espacio de file descriptors no va a ser esparso; pero
    // esto podría mejorarse utilizando otra estructura de datos
    struct item *fds;
    size_t fd_size; // cantidad de elementos posibles de fds

    /** protege el acceso a resolutions jobs */
    pthread_mutex_t resolution_mutex;
    /**
     * lista de trabajos blockeantes que finalizaron y que pueden ser
     * notificados.
     */
    struct blocking_job *resolution_jobs;

    // instalcia epoll para multiplexar (reemplaza todo lo de master/slave y sets del select)
    int epoll_fd;

    // instancia eventfd para manejo de notificaciones (reemplaza señales)
    int event_fd;

    // array de eventos devueltos por el wait de epoll
    struct epoll_event *events;
    size_t events_capacity;
};

/** cantidad máxima de file descriptors (ver SELECTOR_ITEMS_MAX_SIZE en selector.h) */
#define ITEMS_MAX_SIZE SELECTOR_ITEMS_MAX_SIZE

/**
 * determina el tamaño a crecer, generando algo de slack para no tener
 * que realocar constantemente.
 */
static size_t next_capacity(const size_t n)
{
    unsigned bits = 0;
    size_t tmp = n;
    while (tmp != 0)
    {
        tmp >>= 1;
        bits++;
    }
    tmp = 1UL << bits;

    assert(tmp >= n);
    if (tmp > ITEMS_MAX_SIZE)
    {
        tmp = ITEMS_MAX_SIZE;
    }

    return tmp + 1;
}

static inline void item_init(struct item *item)
{
    item->fd = FD_UNUSED;
}

/**
 * inicializa los nuevos items. `last' es el indice anterior.
 * asume que ya está blanqueada la memoria.
 */
static void items_init(fd_selector s, const size_t last)
{
    assert(last <= s->fd_size);
    for (size_t i = last; i < s->fd_size; i++)
    {
        item_init(s->fds + i);
    }
}

/**
 * garantizar cierta cantidad de elemenos en `fds'.
 * Se asegura de que `n' sea un número que la plataforma donde corremos lo
 * soporta
 */
static selector_status ensure_capacity(fd_selector s, const size_t n)
{
    selector_status ret = SELECTOR_SUCCESS;

    const size_t element_size = sizeof(*s->fds);
    if (n < s->fd_size)
    {
        // nada para hacer, entra...
        ret = SELECTOR_SUCCESS;
    }
    else if (n > ITEMS_MAX_SIZE)
    {
        // me estás pidiendo más de lo que se puede.
        ret = SELECTOR_MAXFD;
    }
    else if (NULL == s->fds)
    {
        // primera vez.. alocamos
        const size_t new_size = next_capacity(n);

        s->fds = calloc(new_size, element_size);
        if (NULL == s->fds)
        {
            ret = SELECTOR_ENOMEM;
        }
        else
        {
            s->fd_size = new_size;
            items_init(s, 0);
        }
    }
    else
    {
        // hay que agrandar...
        const size_t new_size = next_capacity(n);
        if (new_size > SIZE_MAX / element_size)
        { // ver MEM07-C
            ret = SELECTOR_ENOMEM;
        }
        else
        {
            struct item *tmp = realloc(s->fds, new_size * element_size);
            if (NULL == tmp)
            {
                ret = SELECTOR_ENOMEM;
            }
            else
            {
                s->fds = tmp;
                const size_t old_size = s->fd_size;
                s->fd_size = new_size;

                items_init(s, old_size);
            }
        }
    }

    return ret;
}

static struct epoll_event interest_to_epoll(const int fd, const fd_interest interest)
{
    struct epoll_event ev = {.data = {.fd = fd}};
    if (interest & OP_READ)
    {
        ev.events |= EPOLLIN;
    }
    if (interest & OP_WRITE)
    {
        ev.events |= EPOLLOUT;
    }
    return ev;
}

fd_selector selector_new(const size_t initial_elements)
{
    size_t size = sizeof(struct fdselector);
    fd_selector ret = malloc(size);
    if (ret != NULL)
    {
        memset(ret, 0x00, size);
        ret->epoll_fd = -1;
        ret->event_fd = -1;

        ret->epoll_fd = epoll_create1(0);
        if (ret->epoll_fd == -1)
        {
            selector_destroy(ret);
            return NULL;
        }

        ret->event_fd = eventfd(0, EFD_NONBLOCK);
        if (ret->event_fd == -1)
        {
            selector_destroy(ret);
            return NULL;
        }

        size_t ev_cap = initial_elements > 0 ? initial_elements : 8;
        ret->events = calloc(ev_cap, sizeof(struct epoll_event));
        if (ret->events == NULL)
        {
            selector_destroy(ret);
            return NULL;
        }
        ret->events_capacity = ev_cap;

        struct epoll_event ev = {
            .events = EPOLLIN,
            .data = {.fd = ret->event_fd},
        };
        if (epoll_ctl(ret->epoll_fd, EPOLL_CTL_ADD, ret->event_fd, &ev) == -1)
        {
            selector_destroy(ret);
            return NULL;
        }

        ret->resolution_jobs = 0;
        pthread_mutex_init(&ret->resolution_mutex, 0);
        if (0 != ensure_capacity(ret, initial_elements))
        {
            selector_destroy(ret);
            ret = NULL;
        }
    }
    return ret;
}

void selector_destroy(fd_selector s)
{
    // lean ya que se llama desde los casos fallidos de _new.
    if (s != NULL)
    {
        if (s->event_fd >= 0)
        {
            close(s->event_fd);
        }

        if (s->fds != NULL)
        {
            for (size_t i = 0; i < s->fd_size; i++)
            {
                if (ITEM_USED(s->fds + i))
                {
                    selector_unregister_fd(s, i);
                }
            }
            pthread_mutex_destroy(&s->resolution_mutex);
            struct blocking_job *j = s->resolution_jobs;
            while (j != NULL)
            {
                struct blocking_job *aux = j;
                j = j->next;
                free(aux);
            }
            free(s->fds);
            s->fds = NULL;
            s->fd_size = 0;
        }

        if (s->epoll_fd >= 0)
        {
            close(s->epoll_fd);
        }

        if (s->events != NULL)
        {
            free(s->events);
            s->events = NULL;
        }

        free(s);
    }
}

#define INVALID_FD(fd) ((fd) < 0 || (fd) >= ITEMS_MAX_SIZE)

selector_status selector_register(fd_selector s,
                                  const int fd,
                                  const fd_handler *handler,
                                  const fd_interest interest,
                                  void *data)
{
    selector_status ret = SELECTOR_SUCCESS;
    // 0. validación de argumentos
    if (s == NULL || INVALID_FD(fd) || handler == NULL)
    {
        ret = SELECTOR_IARGS;
        goto finally;
    }
    // 1. tenemos espacio?
    size_t ufd = (size_t)fd;
    if (ufd > s->fd_size)
    {
        ret = ensure_capacity(s, ufd);
        if (SELECTOR_SUCCESS != ret)
        {
            goto finally;
        }
    }

    // 2. registración
    struct item *item = s->fds + ufd;
    if (ITEM_USED(item))
    {
        ret = SELECTOR_FDINUSE;
        goto finally;
    }
    else
    {
        item->fd = fd;
        item->handler = handler;
        item->interest = interest;
        item->data = data;

        struct epoll_event ev = interest_to_epoll(fd, interest);
        epoll_ctl(s->epoll_fd, EPOLL_CTL_ADD, fd, &ev);
    }

finally:
    return ret;
}

selector_status selector_unregister_fd(fd_selector s,
                                       const int fd)
{
    selector_status ret = SELECTOR_SUCCESS;

    if (NULL == s || INVALID_FD(fd))
    {
        ret = SELECTOR_IARGS;
        goto finally;
    }

    struct item *item = s->fds + fd;
    if (!ITEM_USED(item))
    {
        ret = SELECTOR_IARGS;
        goto finally;
    }

    if (item->handler->handle_close != NULL)
    {
        struct selector_key key = {
            .s = s,
            .fd = item->fd,
            .data = item->data,
        };
        item->handler->handle_close(&key);
    }

    item->interest = OP_NOOP;

    epoll_ctl(s->epoll_fd, EPOLL_CTL_DEL, fd, NULL);

    memset(item, 0x00, sizeof(*item));
    item_init(item);

finally:
    return ret;
}

selector_status selector_set_interest(fd_selector s, int fd, fd_interest i)
{
    selector_status ret = SELECTOR_SUCCESS;

    if (NULL == s || INVALID_FD(fd))
    {
        ret = SELECTOR_IARGS;
        goto finally;
    }
    struct item *item = s->fds + fd;
    if (!ITEM_USED(item))
    {
        ret = SELECTOR_IARGS;
        goto finally;
    }
    item->interest = i;

    struct epoll_event ev = interest_to_epoll(fd, i);
    epoll_ctl(s->epoll_fd, EPOLL_CTL_MOD, fd, &ev);
finally:
    return ret;
}

selector_status selector_set_interest_key(struct selector_key *key, fd_interest i)
{
    selector_status ret;

    if (NULL == key || NULL == key->s || INVALID_FD(key->fd))
    {
        ret = SELECTOR_IARGS;
    }
    else
    {
        ret = selector_set_interest(key->s, key->fd, i);
    }

    return ret;
}

/**
 * se encarga de manejar los resultados del select (ahora epoll).
 * se encuentra separado para facilitar el testing
 */
static void handle_iteration(fd_selector s, const int n_ready)
{
    struct selector_key key = {
        .s = s,
    };

    for (int i = 0; i < n_ready; i++)
    {
        struct epoll_event *ev = &s->events[i];
        int fd = ev->data.fd;

        if (fd == s->event_fd)
        {
            uint64_t val;
            read(s->event_fd, &val, sizeof(val));
            continue;
        }

        struct item *item = &s->fds[fd];
        if (!ITEM_USED(item))
        {
            continue;
        }

        key.data = item->data;
        key.fd = fd;

        if (ev->events & (EPOLLIN | EPOLLERR | EPOLLHUP))
        {
            if (OP_READ & item->interest)
            {
                if (0 == item->handler->handle_read)
                {
                    assert(("OP_READ arrived but no handler. bug!" == 0));
                }
                else
                {
                    item->handler->handle_read(&key);
                }
            }
        }
        if (ev->events & (EPOLLOUT | EPOLLERR | EPOLLHUP))
        {
            if (OP_WRITE & item->interest)
            {
                if (0 == item->handler->handle_write)
                {
                    assert(("OP_WRITE arrived but no handler. bug!" == 0));
                }
                else
                {
                    item->handler->handle_write(&key);
                }
            }
        }
    }
}

static void handle_block_notifications(fd_selector s)
{
    struct selector_key key = {
        .s = s,
    };
    pthread_mutex_lock(&s->resolution_mutex);
    struct blocking_job *j = s->resolution_jobs;
    while (j != NULL)
    {

        struct item *item = s->fds + j->fd;
        if (ITEM_USED(item))
        {
            key.fd = item->fd;
            key.data = item->data;
            item->handler->handle_block(&key);
        }

        struct blocking_job *aux = j;
        j = j->next;
        free(aux);
    }
    s->resolution_jobs = 0;
    pthread_mutex_unlock(&s->resolution_mutex);
}

selector_status selector_notify_block(fd_selector s,
                                      const int fd)
{
    selector_status ret = SELECTOR_SUCCESS;

    // TODO(juan): usar un pool
    struct blocking_job *job = malloc(sizeof(*job));
    if (job == NULL)
    {
        ret = SELECTOR_ENOMEM;
        goto finally;
    }
    job->s = s;
    job->fd = fd;

    // encolamos en el selector los resultados
    pthread_mutex_lock(&s->resolution_mutex);
    job->next = s->resolution_jobs;
    s->resolution_jobs = job;
    pthread_mutex_unlock(&s->resolution_mutex);

    // notificamos al hilo principal (ahora con eventfd en vez de signal)
    const uint64_t val = 1;
    write(s->event_fd, &val, sizeof(val));

finally:
    return ret;
}

selector_status selector_select(fd_selector s)
{
    selector_status ret = SELECTOR_SUCCESS;

    int timeout_ms;
    if (conf.select_timeout.tv_sec == 0 && conf.select_timeout.tv_nsec == 0)
    {
        timeout_ms = 0;
    }
    else
    {
        timeout_ms = (int)(conf.select_timeout.tv_sec * 1000 + conf.select_timeout.tv_nsec / 1000000);
    }

    int fds = epoll_wait(s->epoll_fd, s->events, (int)s->events_capacity,
                         timeout_ms);
    if (-1 == fds)
    {
        switch (errno)
        {
        case EINTR:
            break;
        case EBADF:
            for (size_t i = 0; i < s->fd_size; i++)
            {
                struct item *item = s->fds + i;
                if (ITEM_USED(item) && -1 == fcntl(item->fd, F_GETFD, 0))
                {
                    fprintf(stderr, "Bad descriptor detected: %d\n", item->fd);
                }
            }
            ret = SELECTOR_IO;
            break;
        default:
            ret = SELECTOR_IO;
            goto finally;
        }
    }
    else
    {
        handle_iteration(s, fds);
    }
    if (ret == SELECTOR_SUCCESS)
    {
        handle_block_notifications(s);
    }
finally:
    return ret;
}

int selector_fd_set_nio(const int fd)
{
    int ret = 0;
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
    {
        ret = -1;
    }
    else
    {
        if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
        {
            ret = -1;
        }
    }
    return ret;
}
