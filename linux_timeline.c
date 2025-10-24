/*
* a tool for collect file info like: ctime/mtime/atime/mode/permit/hash ...
*
* compile: gcc -O2 -static -pthread -o timeline linux_timeline.c
* usage: ./timeline
* usage: ./timeline -s $start_path -o $output_path -t $thread_cnt    // default: /  ./  8
*
* author: icingfire
*/
#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>

/* ===================== SHA-256 (no external deps) ===================== */
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    unsigned long long bitlen;
    uint32_t state[8];
} SHA256_CTX;

static const uint32_t k256[64] = {
   0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
   0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
   0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
   0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
   0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
   0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
   0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
   0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void sha256_transform(SHA256_CTX* ctx, const uint8_t data[]) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j + 1] << 16) |
        ((uint32_t)data[j + 2] << 8) | ((uint32_t)data[j + 3]);
    for (; i < 64; ++i)
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e, f, g) + k256[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(SHA256_CTX* ctx) {
    ctx->datalen = 0; ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

static void sha256_update(SHA256_CTX* ctx, const uint8_t data[], size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(SHA256_CTX* ctx, uint8_t hash[]) {
    uint32_t i = ctx->datalen;

    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) ctx->data[i++] = 0x00;
    }
    else {
        ctx->data[i++] = 0x80;
        while (i < 64) ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen += ctx->datalen * 8ULL;
    ctx->data[63] = (uint8_t)(ctx->bitlen);
    ctx->data[62] = (uint8_t)(ctx->bitlen >> 8);
    ctx->data[61] = (uint8_t)(ctx->bitlen >> 16);
    ctx->data[60] = (uint8_t)(ctx->bitlen >> 24);
    ctx->data[59] = (uint8_t)(ctx->bitlen >> 32);
    ctx->data[58] = (uint8_t)(ctx->bitlen >> 40);
    ctx->data[57] = (uint8_t)(ctx->bitlen >> 48);
    ctx->data[56] = (uint8_t)(ctx->bitlen >> 56);
    sha256_transform(ctx, ctx->data);

    for (i = 0; i < 4; ++i) {
        hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0xff;
        hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0xff;
        hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0xff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0xff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0xff;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0xff;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0xff;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0xff;
    }
}

static void sha256_file_hex(const char* path, char* hex /*64+1*/) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { strcpy(hex, "-"); return; }

    SHA256_CTX ctx; sha256_init(&ctx);
    uint8_t buf[1 << 16];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        sha256_update(&ctx, buf, (size_t)n);
    }
    close(fd);
    if (n < 0) { strcpy(hex, "-"); return; }

    uint8_t out[32];
    sha256_final(&ctx, out);
    for (int i = 0; i < 32; i++) sprintf(hex + i * 2, "%02x", out[i]);
    hex[64] = '\0';
}

/* ===================== utils ===================== */
#define HASH_LIMIT (30 * 1024 * 1024)

static const char* EXCLUDES[] = { "/proc", "/sys", "/dev", "/run", NULL };

static int is_excluded(const char* path) {
    for (int i = 0; EXCLUDES[i]; ++i) {
        size_t len = strlen(EXCLUDES[i]);
        if (strncmp(path, EXCLUDES[i], len) == 0 &&
            (path[len] == '/' || path[len] == '\0')) return 1;
    }
    return 0;
}

static void ts_numeric(time_t t, char* buf, size_t sz) {
    struct tm lt;
    localtime_r(&t, &lt);
    strftime(buf, sz, "%Y%m%d%H%M%S", &lt);
}

static const char* type_str(mode_t m) {
    if (S_ISREG(m)) return "regular";
    if (S_ISDIR(m)) return "directory";
    if (S_ISLNK(m)) return "symlink";
    if (S_ISCHR(m)) return "char_device";
    if (S_ISBLK(m)) return "block_device";
    if (S_ISFIFO(m)) return "fifo";
    if (S_ISSOCK(m)) return "socket";
    return "unknown";
}

/* Mode string like rwxrwxrwx, with suid/sgid/sticky bits reflected (s/S/t/T) */
static void mode_string(mode_t m, char out[10]) {
    static const char rwx[] = { 'r','w','x' };
    for (int i = 0; i < 9; i++) out[i] = '-';
    out[9] = '\0';

    mode_t bits[3] = { (m >> 6) & 7, (m >> 3) & 7, m & 7 };
    for (int u = 0; u < 3; ++u) {
        for (int b = 0; b < 3; b++) {
            if (bits[u] & (1 << (2 - b))) out[u * 3 + b] = rwx[b];
        }
    }
    /* suid/sgid/sticky adjustments */
    if (m & S_ISUID) out[2] = (out[2] == 'x') ? 's' : 'S';
    if (m & S_ISGID) out[5] = (out[5] == 'x') ? 's' : 'S';
    if (m & S_ISVTX) out[8] = (out[8] == 'x') ? 't' : 'T';
}

/* CSV escaping: wrap in quotes and double internal quotes */
static void csv_write_escaped(FILE* f, const char* s) {
    fputc('"', f);
    for (const char* p = s; *p; ++p) {
        if (*p == '"') fputc('"', f);
        fputc(*p, f);
    }
    fputc('"', f);
}

/* ===================== thread pool & queue ===================== */

#define QUEUE_CAP 40960

typedef struct {
    char* items[QUEUE_CAP];
    int head, tail;
    int closed;           /* not used for enqueue control; we use inflight to stop */
    unsigned long inflight; /* number of directory tasks enqueued but not yet fully processed */
    pthread_mutex_t mtx;
    pthread_cond_t cv_nonempty;
} dir_queue_t;

static dir_queue_t Q;

static void q_init(dir_queue_t* q) {
    q->head = q->tail = 0;
    q->closed = 0;
    q->inflight = 0;
    pthread_mutex_init(&q->mtx, NULL);
    pthread_cond_init(&q->cv_nonempty, NULL);
}

static int q_is_empty(dir_queue_t* q) {
    return q->head == q->tail;
}

static int q_is_full(dir_queue_t* q) {
    return ((q->tail + 1) % QUEUE_CAP) == q->head;
}

static void q_push(dir_queue_t* q, const char* path) {
    pthread_mutex_lock(&q->mtx);
    if (q_is_full(q)) {
        /* fall back: drop silently; or wait—here we print a warning and drop */
        fprintf(stderr, "Queue overflow, dropping: %s\n", path);
        pthread_mutex_unlock(&q->mtx);
        return;
    }
    q->items[q->tail] = strdup(path);
    q->tail = (q->tail + 1) % QUEUE_CAP;
    q->inflight++; /* track outstanding directory tasks */
    pthread_cond_signal(&q->cv_nonempty);
    pthread_mutex_unlock(&q->mtx);
}

static char* q_pop(dir_queue_t* q, int* should_exit) {
    pthread_mutex_lock(&q->mtx);
    for (;;) {
        if (!q_is_empty(q)) {
            char* s = q->items[q->head];
            q->head = (q->head + 1) % QUEUE_CAP;
            pthread_mutex_unlock(&q->mtx);
            *should_exit = 0;
            return s;
        }
        /* If nothing queued and no inflight, all work is done */
        if (q->inflight == 0) {
            *should_exit = 1;
            pthread_mutex_unlock(&q->mtx);
            return NULL;
        }
        pthread_cond_wait(&q->cv_nonempty, &q->mtx);
    }
}

/* called by worker when it completely finished processing one directory */
static void q_task_done(dir_queue_t* q) {
    pthread_mutex_lock(&q->mtx);
    if (q->inflight > 0) q->inflight--;
    /* if inflight==0, wake all waiters so they can exit */
    if (q->inflight == 0)
        pthread_cond_broadcast(&q->cv_nonempty);
    pthread_mutex_unlock(&q->mtx);
}

/* ===================== global output ===================== */

static FILE* g_out = NULL;
static pthread_mutex_t g_out_mtx = PTHREAD_MUTEX_INITIALIZER;

/* ===================== core processing ===================== */

static void format_join(char out[PATH_MAX], const char* dir, const char* name) {
    if (strcmp(dir, "/") == 0) snprintf(out, PATH_MAX, "/%s", name);
    else snprintf(out, PATH_MAX, "%s/%s", dir, name);
}

static void write_file_csv(const char* path, const struct stat* st) {
    char cbuf[16], mbuf[16], abuf[16], modes[10], hash[65];
    ts_numeric(st->st_ctime, cbuf, sizeof(cbuf));
    ts_numeric(st->st_mtime, mbuf, sizeof(mbuf));
    ts_numeric(st->st_atime, abuf, sizeof(abuf));
    mode_string(st->st_mode, modes);
    if (S_ISREG(st->st_mode) && st->st_size <= HASH_LIMIT) sha256_file_hex(path, hash);
    else strcpy(hash, "-");

    const char* tstr = type_str(st->st_mode);

    pthread_mutex_lock(&g_out_mtx);
    csv_write_escaped(g_out, path);
    fprintf(g_out, ",%s,%s,%s,%lld,%s,%s,%s,%u,%u\n",
        cbuf, mbuf, abuf,
        (long long)st->st_size,
        modes,
        hash,
        tstr,
        (unsigned)st->st_uid,
        (unsigned)st->st_gid);
    pthread_mutex_unlock(&g_out_mtx);
}

static void process_directory(const char* dirpath) {
    /* Skip excluded roots early */
    if (is_excluded(dirpath)) { q_task_done(&Q); return; }

    struct stat st_dir;
    if (lstat(dirpath, &st_dir) == -1) { q_task_done(&Q); return; }

    /* also write the directory itself as a row */
    write_file_csv(dirpath, &st_dir);

    DIR* dp = opendir(dirpath);
    if (!dp) { q_task_done(&Q); return; }

    struct dirent* de;
    char path[PATH_MAX];

    while ((de = readdir(dp)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;

        format_join(path, dirpath, de->d_name);

        struct stat st;
        if (lstat(path, &st) == -1) {
            continue;
        }

        /* if it's a directory (not excluded), enqueue */
        if (S_ISDIR(st.st_mode) && !is_excluded(path)) {
            q_push(&Q, path);
        }
        else {
            /* output file/entry row */
            write_file_csv(path, &st);
        }
        /* don't follow symlinks as directories */
    }

    closedir(dp);
    q_task_done(&Q);
}

/* worker thread */
static void* worker(void* arg) {
    (void)arg;
    for (;;) {
        int should_exit = 0;
        char* dir = q_pop(&Q, &should_exit);
        if (should_exit) break;
        if (!dir) continue;
        process_directory(dir);
        free(dir);
    }
    return NULL;
}

/* ===================== main ===================== */

static void make_ts(char* buf, size_t sz) {
    time_t now = time(NULL);
    ts_numeric(now, buf, sz);
}

static void print_time() {
    time_t t;
    struct tm* tm_info;
    char buffer[64];

    time(&t);
    tm_info = localtime(&t);

    // time format YYYY-MM-DD HH:MM:SS
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm_info);

    printf("Time: %s\n", buffer);
}


int main(int argc, char* argv[]) {

    char *start_path = "/";
    char *output_path = ".";
    int threads = 8;
    int opt;
	int silent = 0;

    while ((opt = getopt(argc, argv, "s:o:t:S")) != -1) {
        switch (opt) {
            case 's':
                start_path = optarg;
                int t_len = strlen(start_path);
                if (start_path[t_len-1] == '/')
                    start_path[t_len-1] = 0;
                break;
            case 'o':
                output_path = optarg;
                break;
            case 't':
                threads = atoi(optarg);
                break;
            case 'S':
                silent = 1;
                break;
            default:
                fprintf(stderr, "Usage: %s [-s search_path] [-o output_path] [-t threads]\n", argv[0]);
                return 1;
        }
    }
	
	

    /* build output file name with timestamp */
    char ts[32], fname[128];
    make_ts(ts, sizeof(ts));
    snprintf(fname, sizeof(fname), "%s/timeline_%s.csv", output_path, ts);

    g_out = fopen(fname, "w");
    if (!g_out) {
        perror("fopen");
        return 1;
    }

    /* header */
    fprintf(g_out, "path,ctime,mtime,atime,size,mode,sha256,type,uid,gid\n");

    /* init queue & push start directory */
    q_init(&Q);
    q_push(&Q, start_path);
    if (silent == 0)
        print_time();

    /* create workers */
    pthread_t* tids = (pthread_t*)calloc((size_t)threads, sizeof(pthread_t));
    for (int i = 0; i < threads; i++) {
        if (pthread_create(&tids[i], NULL, worker, NULL) != 0) {
            perror("pthread_create");
            /* continue launching fewer threads */
        }
    }

    /* wait workers */
    for (int i = 0; i < threads; i++) {
        if (tids[i]) pthread_join(tids[i], NULL);
    }
    free(tids);
	fclose(g_out);
	
    if (silent == 0) {
        print_time();
        fprintf(stderr, "Done. Output: %s\n", fname);
    }
    
    return 0;
}