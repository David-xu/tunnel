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

static const uint32_t g_crc32c_table[256] = {
  0x00000000L, 0xF26B8303L, 0xE13B70F7L, 0x1350F3F4L,
  0xC79A971FL, 0x35F1141CL, 0x26A1E7E8L, 0xD4CA64EBL,
  0x8AD958CFL, 0x78B2DBCCL, 0x6BE22838L, 0x9989AB3BL,
  0x4D43CFD0L, 0xBF284CD3L, 0xAC78BF27L, 0x5E133C24L,
  0x105EC76FL, 0xE235446CL, 0xF165B798L, 0x030E349BL,
  0xD7C45070L, 0x25AFD373L, 0x36FF2087L, 0xC494A384L,
  0x9A879FA0L, 0x68EC1CA3L, 0x7BBCEF57L, 0x89D76C54L,
  0x5D1D08BFL, 0xAF768BBCL, 0xBC267848L, 0x4E4DFB4BL,
  0x20BD8EDEL, 0xD2D60DDDL, 0xC186FE29L, 0x33ED7D2AL,
  0xE72719C1L, 0x154C9AC2L, 0x061C6936L, 0xF477EA35L,
  0xAA64D611L, 0x580F5512L, 0x4B5FA6E6L, 0xB93425E5L,
  0x6DFE410EL, 0x9F95C20DL, 0x8CC531F9L, 0x7EAEB2FAL,
  0x30E349B1L, 0xC288CAB2L, 0xD1D83946L, 0x23B3BA45L,
  0xF779DEAEL, 0x05125DADL, 0x1642AE59L, 0xE4292D5AL,
  0xBA3A117EL, 0x4851927DL, 0x5B016189L, 0xA96AE28AL,
  0x7DA08661L, 0x8FCB0562L, 0x9C9BF696L, 0x6EF07595L,
  0x417B1DBCL, 0xB3109EBFL, 0xA0406D4BL, 0x522BEE48L,
  0x86E18AA3L, 0x748A09A0L, 0x67DAFA54L, 0x95B17957L,
  0xCBA24573L, 0x39C9C670L, 0x2A993584L, 0xD8F2B687L,
  0x0C38D26CL, 0xFE53516FL, 0xED03A29BL, 0x1F682198L,
  0x5125DAD3L, 0xA34E59D0L, 0xB01EAA24L, 0x42752927L,
  0x96BF4DCCL, 0x64D4CECFL, 0x77843D3BL, 0x85EFBE38L,
  0xDBFC821CL, 0x2997011FL, 0x3AC7F2EBL, 0xC8AC71E8L,
  0x1C661503L, 0xEE0D9600L, 0xFD5D65F4L, 0x0F36E6F7L,
  0x61C69362L, 0x93AD1061L, 0x80FDE395L, 0x72966096L,
  0xA65C047DL, 0x5437877EL, 0x4767748AL, 0xB50CF789L,
  0xEB1FCBADL, 0x197448AEL, 0x0A24BB5AL, 0xF84F3859L,
  0x2C855CB2L, 0xDEEEDFB1L, 0xCDBE2C45L, 0x3FD5AF46L,
  0x7198540DL, 0x83F3D70EL, 0x90A324FAL, 0x62C8A7F9L,
  0xB602C312L, 0x44694011L, 0x5739B3E5L, 0xA55230E6L,
  0xFB410CC2L, 0x092A8FC1L, 0x1A7A7C35L, 0xE811FF36L,
  0x3CDB9BDDL, 0xCEB018DEL, 0xDDE0EB2AL, 0x2F8B6829L,
  0x82F63B78L, 0x709DB87BL, 0x63CD4B8FL, 0x91A6C88CL,
  0x456CAC67L, 0xB7072F64L, 0xA457DC90L, 0x563C5F93L,
  0x082F63B7L, 0xFA44E0B4L, 0xE9141340L, 0x1B7F9043L,
  0xCFB5F4A8L, 0x3DDE77ABL, 0x2E8E845FL, 0xDCE5075CL,
  0x92A8FC17L, 0x60C37F14L, 0x73938CE0L, 0x81F80FE3L,
  0x55326B08L, 0xA759E80BL, 0xB4091BFFL, 0x466298FCL,
  0x1871A4D8L, 0xEA1A27DBL, 0xF94AD42FL, 0x0B21572CL,
  0xDFEB33C7L, 0x2D80B0C4L, 0x3ED04330L, 0xCCBBC033L,
  0xA24BB5A6L, 0x502036A5L, 0x4370C551L, 0xB11B4652L,
  0x65D122B9L, 0x97BAA1BAL, 0x84EA524EL, 0x7681D14DL,
  0x2892ED69L, 0xDAF96E6AL, 0xC9A99D9EL, 0x3BC21E9DL,
  0xEF087A76L, 0x1D63F975L, 0x0E330A81L, 0xFC588982L,
  0xB21572C9L, 0x407EF1CAL, 0x532E023EL, 0xA145813DL,
  0x758FE5D6L, 0x87E466D5L, 0x94B49521L, 0x66DF1622L,
  0x38CC2A06L, 0xCAA7A905L, 0xD9F75AF1L, 0x2B9CD9F2L,
  0xFF56BD19L, 0x0D3D3E1AL, 0x1E6DCDEEL, 0xEC064EEDL,
  0xC38D26C4L, 0x31E6A5C7L, 0x22B65633L, 0xD0DDD530L,
  0x0417B1DBL, 0xF67C32D8L, 0xE52CC12CL, 0x1747422FL,
  0x49547E0BL, 0xBB3FFD08L, 0xA86F0EFCL, 0x5A048DFFL,
  0x8ECEE914L, 0x7CA56A17L, 0x6FF599E3L, 0x9D9E1AE0L,
  0xD3D3E1ABL, 0x21B862A8L, 0x32E8915CL, 0xC083125FL,
  0x144976B4L, 0xE622F5B7L, 0xF5720643L, 0x07198540L,
  0x590AB964L, 0xAB613A67L, 0xB831C993L, 0x4A5A4A90L,
  0x9E902E7BL, 0x6CFBAD78L, 0x7FAB5E8CL, 0x8DC0DD8FL,
  0xE330A81AL, 0x115B2B19L, 0x020BD8EDL, 0xF0605BEEL,
  0x24AA3F05L, 0xD6C1BC06L, 0xC5914FF2L, 0x37FACCF1L,
  0x69E9F0D5L, 0x9B8273D6L, 0x88D28022L, 0x7AB90321L,
  0xAE7367CAL, 0x5C18E4C9L, 0x4F48173DL, 0xBD23943EL,
  0xF36E6F75L, 0x0105EC76L, 0x12551F82L, 0xE03E9C81L,
  0x34F4F86AL, 0xC69F7B69L, 0xD5CF889DL, 0x27A40B9EL,
  0x79B737BAL, 0x8BDCB4B9L, 0x988C474DL, 0x6AE7C44EL,
  0xBE2DA0A5L, 0x4C4623A6L, 0x5F16D052L, 0xAD7D5351L
};

/*
 * Steps through buffer one byte at at time, calculates reflected
 * crc using table.
 */

uint32_t fgfw_crc32c_sw(const void *data, uint64_t length)
{
    //uint32_t crc = ~0;
    uint32_t crc = 0;
    uint8_t *p = (uint8_t *)data;

    while (length--)
        crc = g_crc32c_table[(crc ^ *p++) & 0xFFL] ^ (crc >> 8);

    return crc;
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

#define STDIVCTRL_EMPTYSUBSTR  1

int fgfw_stdiv
(
	char *buf,			/* input */
	int buflen,			/* input */
	int n_argv,			/* input: sizeof argv */
	char *argv[],		/* output */
	uint32_t len[],		/* output */
	int n_divflag,		/* input */
	char *divflag,		/* input */
	uint32_t ctrl		/* input */
)
{
	int i, j, ret = 0, state = 0;		/* 0: begin, 1: not div char 2: div char */

	for (i = 0; i < n_argv; i++)
	{
		argv[i] = NULL;
		len[i] = 0;
	}

	for (i = 0; i < buflen;)
	{
		for (j = 0; j < n_divflag; j++)
		{
			if (buf[i] == divflag[j])
			{
				/* ok, we find one div charactor */

				switch (state)
				{
				case 0:
				case 1:
					state = 2;
					break;
				case 2:
					if (ctrl & STDIVCTRL_EMPTYSUBSTR)
					{
						/* need to save this empty flag */

						if (ret == n_argv)
							return ret;

						ret++;
					}
					break;
				default:
                    break;
				}

				goto stdiv_nextch;
			}
		}

		/* reach here, the buf[i] is NOT the div charactor */
		switch (state)
		{
		case 0:
		case 2:
			if (ret == n_argv)
				return ret;

			argv[ret] = &(buf[i]);
			len[ret] = 1;
			ret++;

			state = 1;

			break;
		case 1:
			(len[ret - 1])++;
			break;
		default:
            break;
		}

stdiv_nextch:

        i++;
	}

    return ret;
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

int fgfw_bitmap_init_ex(fgfw_bitmap_t *bm, const char *name, uint32_t n_total, uint32_t id_base, int clear)
{
    bm->magic = IOHUB_BITMAP_MAGIC;
    bm->id_base = id_base;
    bm->n_total = n_total;

    memset(bm->name, 0, sizeof(bm->name));
    strncpy(bm->name, name, sizeof(bm->name) - 1);

    if (clear) {
        bm->n_free = 0;
        memset(bm->bm, 0, FGFW_BITMAP_BMARRAY_SIZE(bm) * sizeof(*bm->bm));
    } else {
        bm->n_free = n_total;
        memset(bm->bm, 0xff, FGFW_BITMAP_BMARRAY_SIZE(bm) * sizeof(*bm->bm));
    }

    return 0;
}

int fgfw_bitmap_alloc(fgfw_bitmap_t *bm, uint32_t n, uint32_t *res)
{
    uint32_t i, j, max = FGFW_BITMAP_BMARRAY_SIZE(bm), cnt = 0;

    if ((bm == NULL) || (res == NULL) || (n == 0)) {
        /* invalid param */
        return -1;
    }

    if (n > bm->n_free) {
        /* no enough resource */
        return -2;
    }

    for (i = 0; i < max; i++) {
        while (bm->bm[i]) {
            j = __builtin_ffsl(bm->bm[i]) - 1;
            /* clear bitmap */
            bm->bm[i] &= ~(1ULL << j);
            res[cnt++] = bm->id_base + i * 64 + j;

            if (cnt == n) {
                goto _ret;
            }
        }
    }
_ret:
    if (cnt != n) {
        fgfw_err("bitmap %s, n_total %d, n_free %d, but no enough in bitmap",
            bm->name, bm->n_total, bm->n_free);
        return -2;
    }

    bm->n_free -= n;

    return 0;
}

int fgfw_bitmap_alloc_specified(fgfw_bitmap_t *bm, uint32_t specified_id)
{
    uint32_t i, j, id;
    if (bm == NULL) {
        /* invalid param */
        return -1;
    }

    if ((specified_id < bm->id_base) || (specified_id >= (bm->id_base + bm->n_total))) {
        /* invalid id in ids */
        fgfw_err("bm %s, id_base %d, n_total %d, specified_id %d\n",
            bm->name, bm->id_base, bm->n_total, specified_id);
        return -2;
    }

    id = specified_id - bm->id_base;
    i = id / 64;
    j = id % 64;

    if ((bm->bm[i] & (1ULL << j)) == 0) {
        /* specified id has already been occupied */
        return -3;
    }

    bm->bm[i] &= ~(1ULL << j);
    bm->n_free--;

    return 0;
}

int fgfw_bitmap_free(fgfw_bitmap_t *bm, uint32_t n, uint32_t *ids)
{
    uint32_t idx, i, j, id;
    if ((bm == NULL) || (ids == NULL) || (n == 0)) {
        /* invalid param */
        return -1;
    }

    for (idx = 0; idx < n; idx++) {
        id = ids[idx];

        if ((id < bm->id_base) || (id >= (bm->id_base + bm->n_total))) {
            fgfw_err("bm %s, id_base %d, n_total %d, ids[%d] %d\n",
                bm->name, bm->id_base, bm->n_total, idx, id);
            return -2;
        }

        id -= bm->id_base;

        i = id / 64;
        j = id % 64;

        if ((bm->bm[i] & (1ULL << j)) == 0) {
            /**/
            bm->bm[i] |= 1ULL << j;
            bm->n_free++;
        }
    }

    return 0;
}

int fgfw_bitmap_query_specified(fgfw_bitmap_t *bm, uint32_t specified_id)
{
    uint32_t i, j, id;
    if (bm == NULL) {
        /* invalid param */
        return -1;
    }

    if ((specified_id < bm->id_base) || (specified_id >= (bm->id_base + bm->n_total))) {
        /* invalid id in ids */
        fgfw_err("bm %s, id_base %d, n_total %d, specified_id %d\n",
            bm->name, bm->id_base, bm->n_total, specified_id);
        return -2;
    }

    id = specified_id - bm->id_base;
    i = id / 64;
    j = id % 64;

    if ((bm->bm[i] & (1ULL << j)) == 0) {
        /* specified id has already been occupied */
        return 0;
    }

    return 1;
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

int fgfw_range_res_init(fgfw_range_res_t *mngr, uint64_t base, uint64_t size, int empty)
{
    fgfw_initlisthead(&(mngr->freelist));
    mngr->base = base;
    mngr->size = size;
    mngr->free = size;
    mngr->n_node = 0;
    mngr->putget_cnt = 0;

    /*  */
    if (empty == 0) {
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
        fgfw_assert(0);
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

void fgfw_range_res_dump(fgfw_range_res_t *mngr, const char *prefix)
{
    uint32_t i = 0;
    fgfw_range_res_node_t *p;

    FGFW_LISTENTRYWALK(p, &(mngr->freelist), node) {
        fgfw_log("%s[0x%016lx, 0x%016lx)\n", prefix, p->base, p->base + p->size);
        i++;
    }

    fgfw_log("%smngr->base 0x%016lx, mngr->size 0x%016lx, mngr->putget_cnt %d, mngr->n_node %d, i %d\n",
        prefix, mngr->base, mngr->base + mngr->size, mngr->putget_cnt, mngr->n_node, i);
    if (i != mngr->n_node) {
        fgfw_err("mngr->node %d != i %d\n", mngr->n_node, i);
    }
}
