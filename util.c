#include "pub.h"

#define SECS_PER_HOUR   (60 * 60)
#define SECS_PER_DAY    (SECS_PER_HOUR * 24)
#define DIV(a, b) ((a) / (b) - ((a) % (b) < 0))
#define QEMU_TIME_STRING_BUFLEN \
    (4 + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 3 + 5 + 1)

#define LEAPS_THRU_END_OF(y) (DIV (y, 4) - DIV (y, 100) + DIV (y, 400))

static const unsigned short int __mon_yday[2][13] = {
    /* Normal years.  */
    { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365 },
    /* Leap years.  */
    { 0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366 }
};

#define is_leap_year(y) \
    ((y) % 4 == 0 && ((y) % 100 != 0 || (y) % 400 == 0))

static int qemu_time_fields_then_raw(unsigned long when, struct tm *fields)
{
    /* This code is taken from GLibC under terms of LGPLv2+ */
    long int days, rem, y;
    const unsigned short int *ip;
    unsigned long long whenSecs = when / 1000ull;
    unsigned int offset = 0; /* We hardcoded GMT */

    days = whenSecs / SECS_PER_DAY;
    rem = whenSecs % SECS_PER_DAY;
    rem += offset;
    while (rem < 0) {
        rem += SECS_PER_DAY;
        --days;
    }
    while (rem >= SECS_PER_DAY) {
        rem -= SECS_PER_DAY;
        ++days;
    }
    fields->tm_hour = rem / SECS_PER_HOUR;
    rem %= SECS_PER_HOUR;
    fields->tm_min = rem / 60;
    fields->tm_sec = rem % 60;
    /* January 1, 1970 was a Thursday.  */
    fields->tm_wday = (4 + days) % 7;
    if (fields->tm_wday < 0)
        fields->tm_wday += 7;
    y = 1970;

    while (days < 0 || days >= (is_leap_year(y) ? 366 : 365)) {
        /* Guess a corrected year, assuming 365 days per year.  */
        long int yg = y + days / 365 - (days % 365 < 0);

      /* Adjust DAYS and Y to match the guessed year.  */
      days -= ((yg - y) * 365
               + LEAPS_THRU_END_OF(yg - 1)
               - LEAPS_THRU_END_OF(y - 1));
      y = yg;
    }
    fields->tm_year = y - 1900;

    fields->tm_yday = days;
    ip = __mon_yday[is_leap_year(y)];
    for (y = 11; days < (long int) ip[y]; --y)
        continue;
    days -= ip[y];
    fields->tm_mon = y;
    fields->tm_mday = days + 1;
    return 0;
}

static int qemu_time_string_then_raw(unsigned long when, char *buf)
{
	struct tm fields;
	if (qemu_time_fields_then_raw(when, &fields) < 0)
		return -1;

	fields.tm_year += 1900;
	fields.tm_mon += 1;

	if (snprintf(buf, QEMU_TIME_STRING_BUFLEN,
					"%4d-%02d-%02d %02d:%02d:%02d.%03d",
					fields.tm_year, fields.tm_mon, fields.tm_mday,
					fields.tm_hour, fields.tm_min, fields.tm_sec,
					(int) (when % 1000)) >= QEMU_TIME_STRING_BUFLEN) {
		return -1;
	}

	return 0;
}

int qemu_time_millis_now_raw(unsigned long *now)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_REALTIME, &ts) < 0)
		return -1;

	*now = (ts.tv_sec * 1000ull) + (ts.tv_nsec / (1000ull * 1000ull));
	/* change to beijing time */
	*now += 8 * 3600 * 1000;
	return 0;
}

int time_string_now_raw(char *buf)
{
	unsigned long now;
	if (qemu_time_millis_now_raw(&now) < 0)
		return -1;

	return qemu_time_string_then_raw(now, buf);
}

int fgfw_printf(const char *fmt, ...)
{
    char buf[32];
    char tmp[1024];
    int n = 0;
    va_list args;

    time_string_now_raw(buf);

    n += snprintf(tmp + n, sizeof(tmp) - n, "%s| ", buf);
    va_start(args, fmt);
    n += vsnprintf(tmp + n, sizeof(tmp) - n, fmt, args);
    va_end(args);

    printf("%s", tmp);

    return n;
}

void fgfw_aes_encrypt(const unsigned char *key, const unsigned char *input, unsigned char *output) {
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);
    AES_ecb_encrypt(input, output, &aes_key, AES_ENCRYPT);
}

void fgfw_aes_decrypt(const unsigned char *key, const unsigned char *input, unsigned char *output) {
    AES_KEY aes_key;
    AES_set_decrypt_key(key, 128, &aes_key);
    AES_ecb_encrypt(input, output, &aes_key, AES_DECRYPT);
}

void fgfw_hexdump(const void *buf, uint32_t len)
{
    const uint32_t line_w = 16;
    uint32_t i, v, off;
    char strbuf[256];

    for (i = 0; i < len; i++) {
        off = i % line_w;
        if (off == 0) {
            memset(strbuf, ' ', sizeof(strbuf));
            strbuf[line_w] = '|';
            strbuf[line_w * 4 + 1] = '\0';
        }

        v = ((uint8_t *)buf)[i];

        strbuf[line_w + 1 + off * 3] = fgfw_n2c(v >> 4);
        strbuf[line_w + 1 + off * 3 + 1] = fgfw_n2c(v & 0xf);

        if ((v >= 32) && (v <= 126)) {
            strbuf[off] = (char)v;
        } else {
            strbuf[off] = '.';
        }

        if (off == (line_w - 1)) {
            fgfw_log("%s\n", strbuf);
        }
    }
    if (len % line_w) {
        fgfw_log("%s\n", strbuf);
    }
}

static fgfw_range_res_node_t *fgfw_range_res_get_node(fgfw_range_res_t *mngr)
{
    fgfw_range_res_node_t *ret;
    ret = malloc(sizeof(fgfw_range_res_node_t));
    if (ret) {
        mngr->putget_cnt++;
    }

    return ret;
}

static void fgfw_range_res_put_node(fgfw_range_res_t *mngr, fgfw_range_res_node_t *node)
{
    mngr->putget_cnt--;
    free(node);
}

int fgfw_range_res_init(fgfw_range_res_t *mngr, uint64_t base, uint64_t size)
{
    fgfw_initlisthead(&(mngr->freelist));
    mngr->base = base;
    mngr->size = size;
    mngr->free = size;
    mngr->n_node = 0;
    mngr->putget_cnt = 0;

    /*  */
    if (size) {
        fgfw_range_res_node_t *p;

        p = fgfw_range_res_get_node(mngr);
        if (p == NULL) {
            fgfw_err("no resource.\n");
            return -1;
        }

        p->base = base;
        p->size = size;
        fgfw_listadd_tail(&(p->node), &(mngr->freelist));
        mngr->n_node++;
    }

    return 0;
}

int fgfw_range_res_uninit(fgfw_range_res_t *mngr)
{
    fgfw_range_res_node_t *p, *n;

    if (!mngr->size) {
        /* maybe not init yet, do nothing */
        return 0;
    }

    FGFW_LISTENTRYWALK_SAVE(p, n, &(mngr->freelist), node) {
        fgfw_range_res_put_node(mngr, p);
    }

    return 0;
}

/* ret -1: no resource */
uint64_t fgfw_range_res_alloc(fgfw_range_res_t *mngr, uint64_t size)
{
    fgfw_range_res_node_t *p, *n;
    uint64_t ret = FGFW_RANGE_RES_INVALID;

    if (mngr->n_node == 0) {
        return ret;
    }

    FGFW_LISTENTRYWALK_SAVE(p, n, &(mngr->freelist), node) {
        if (p->size >= size) {
            ret = p->base;
            p->base += size;
            p->size -= size;

            if (p->size == 0) {
                fgfw_listdel(&(p->node));
                mngr->n_node--;
                fgfw_range_res_put_node(mngr, p);
            }
            mngr->free -= size;

            break;
        }
    }

    return ret;
}

int fgfw_range_res_merge(fgfw_range_res_t *mngr, uint64_t base[2], uint64_t num[2], uint32_t dir)
{
    fgfw_range_res_node_t *p, *n;

    if (mngr->n_node < 2) {
        return -1;
    }

    p = FGFW_GETCONTAINER(mngr->freelist.next, typeof(*p), node);
    n = FGFW_GETCONTAINER(p->node.next, typeof(*n), node);

    if (p->node.next == &mngr->freelist) {
        fgfw_err("freelist something wrong, n_node(%u) freelist(%p) freelist->next(%p) freelist->next->next(%p).\n",
            mngr->n_node, mngr->freelist.next, p->node.next, n->node.next);
        return -1;
    }

    if (fgfw_isrange_overlap(p->base, p->size, n->base, n->size)) {
        /* over lap */
        fgfw_err("[0x%lx, 0x%lx) overlap with free node [0x%lx, 0x%lx) something wrong.\n",
            p->base, p->base + p->size, n->base, n->base + n->size);
        return -1;
    }

    base[0] = p->base;
    num[0] = p->size;
    base[1] = n->base;
    num[1] = n->size;

    if (!dir) {
        p->base = n->base - p->size;
    }

    p->size = p->size + n->size;
    fgfw_listdel(&(n->node));
    fgfw_range_res_put_node(mngr, n);
    mngr->n_node--;

    return 0;
}

/*
 * size: 0, alloc whole node matched by base
 */
int fgfw_range_res_alloc_specified(fgfw_range_res_t *mngr, uint64_t base, uint64_t *size)
{
    fgfw_range_res_node_t *p, *n, *newp;

    FGFW_LISTENTRYWALK_SAVE(p, n, &(mngr->freelist), node) {
        if ((p->base <= base) && ((p->base + p->size) >= (base + *size))) {
            if (p->base == base) {
                if (*size == 0) {
                    *size = p->size;
                }

                if ((p->base + p->size) == (base + *size)) {
                    /* delete this node */
                    fgfw_listdel(&(p->node));
                    mngr->n_node--;
                    fgfw_range_res_put_node(mngr, p);
                } else {
                    p->base = base + *size;
                    p->size -= *size;
                }
            } else {
                if (*size == 0) {
                    return -3;
                }

                if ((p->base + p->size) == (base + *size)) {
                    p->size -= *size;
                } else {
                    /* split */
                    newp = fgfw_range_res_get_node(mngr);
                    if (newp == NULL) {
                        fgfw_err("no resource.\n");
                        return -2;
                    }

                    /* add new node */
                    newp->base = base + *size;
                    newp->size = p->base + p->size - newp->base;
                    fgfw_listadd(&(newp->node), &(p->node));
                    mngr->n_node++;

                    /* old one motify */
                    p->size = base - p->base;
                }
            }

            mngr->free -= *size;

            return 0;
        }
    }

    return -1;
}

void  fgfw_range_res_free(fgfw_range_res_t *mngr, uint64_t base, uint64_t size)
{
    fgfw_range_res_node_t *p, *n, *newp;

    if (size == 0) {
        return;
    }

    if ((base < mngr->base) || ((base + size) > (mngr->base + mngr->size))) {
        fgfw_err("[0x%lx, 0x%lx) outof mngr range [0x%lx, 0x%lx)\n",
            base, size, mngr->base, mngr->base + mngr->size);
        return;
    }

    FGFW_LISTENTRYWALK_SAVE(p, n, &(mngr->freelist), node) {
        if ((base + size) < p->base) {
            /* alloc new node and insert before p->node */
            break;
        } else if ((base + size) == p->base) {
            /* combine with p, front */
            p->base = base;
            p->size = p->size + size;
            goto _finish;
        } else if (fgfw_isrange_overlap(base, size, p->base, p->size)) {
            /* over lap */
            fgfw_err("[0x%lx, 0x%lx) overlap with free node [0x%lx, 0x%lx) something wrong.\n",
                base, base + size, p->base, p->base + p->size);
            return;
        } else if ((p->base + p->size) == base) {
            /* combine with p, end */
            p->size += size;

            if (&(n->node) != &(mngr->freelist)) {
                if ((p->base + p->size) > n->base) {
                    p->size -= size;
                    fgfw_err("[0x%lx, 0x%lx) overlap with free node [0x%lx, 0x%lx) something wrong.\n",
                        base, base + size, n->base, n->base + n->size);
                } else if ((p->base + p->size) == n->base) {
                    p->size += n->size;

                    /* del next node */
                    fgfw_listdel(&(n->node));
                    mngr->n_node--;
                    fgfw_range_res_put_node(mngr, n);
                }
            }
            goto _finish;
        }
    }

    newp = fgfw_range_res_get_node(mngr);
    if (newp == NULL) {
        fgfw_err("no resource.\n");
        return;
    }

    /* add new node before p */
    newp->base = base;
    newp->size = size;
    fgfw_listadd_tail(&(newp->node), &(p->node));
    mngr->n_node++;

_finish:
    mngr->free += size;
}

void fgfw_range_res_dump(fgfw_range_res_t *mngr)
{
    uint32_t i = 0;
    fgfw_range_res_node_t *p;

    FGFW_LISTENTRYWALK(p, &(mngr->freelist), node) {
        fgfw_log("[0x%016lx, 0x%016lx)\n", p->base, p->base + p->size);
        i++;
    }

    fgfw_log("mngr->base 0x%016lx, mngr->size 0x%016lx, mngr->putget_cnt %d, mngr->n_node %d, i %d\n",
        mngr->base, mngr->base + mngr->size, mngr->putget_cnt, mngr->n_node, i);
    if (i != mngr->n_node) {
        fgfw_err("mngr->node %d != i %d\n", mngr->n_node, i);
    }
}
