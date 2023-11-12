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

uint32_t rn_crc32c_sw(const void *data, uint64_t length)
{
    //uint32_t crc = ~0;
    uint32_t crc = 0;
    uint8_t *p = (uint8_t *)data;

    while (length--)
        crc = g_crc32c_table[(crc ^ *p++) & 0xFFL] ^ (crc >> 8);

    return crc;
}

// uint64_t g_dbgprint_flag = 0xffffffffffffffffull;
uint64_t g_dbgprint_flag = 0;

int rn_printf(const char *fmt, ...)
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

#ifdef RN_ANDROID_ENV
#include <android/log.h>
#define VACC_HOST_PRINT(...)        __android_log_print(ANDROID_LOG_DEBUG, "rn_log", __VA_ARGS__)
    VACC_HOST_PRINT("%s", tmp);
#else
    printf("%s", tmp);
#endif
    return n;
}

#define STDIVCTRL_EMPTYSUBSTR  1

int rn_stdiv
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

void rn_hexdump(const void *buf, uint32_t len)
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

        strbuf[line_w + 1 + off * 3] = rn_n2c(v >> 4);
        strbuf[line_w + 1 + off * 3 + 1] = rn_n2c(v & 0xf);

        if ((v >= 32) && (v <= 126)) {
            strbuf[off] = (char)v;
        } else {
            strbuf[off] = '.';
        }

        if (off == (line_w - 1)) {
            rn_log("%s\n", strbuf);
        }
    }
    if (len % line_w) {
        rn_log("%s\n", strbuf);
    }
}

rn_gpfifo_t * rn_gpfifo_create(uint32_t depth, uint32_t element_size)
{
    rn_gpfifo_t *ret;
    uint32_t space_size = sizeof(rn_gpfifo_t) + depth * element_size;

    rn_assert(depth != 0);
    rn_assert((depth & (depth - 1)) == 0);
    rn_assert(element_size != 0);

    ret = malloc(space_size);
    rn_assert(ret != NULL);

    memset(ret, 0, sizeof(rn_gpfifo_t));

    ret->depth = depth;
    ret->element_size = element_size;

    return ret;
}

int rn_gpfifo_destroy(rn_gpfifo_t *gpfifo)
{
    free(gpfifo);

    return RN_RETVALUE_OK;
}

rn_pkb_pool_t * rn_pkb_pool_create(uint32_t total_pkb_num, uint32_t bufsize)
{
    rn_pkb_pool_t *pkb_pool;
    rn_pkb_t *pkb;
    uint32_t one_pkb_size = (sizeof(rn_pkb_t) + bufsize);
    uint32_t space_size = sizeof(rn_pkb_pool_t) + total_pkb_num * one_pkb_size;
    uint32_t i;

    pkb_pool = malloc(space_size);
    pkb_pool->total_pkb_num = total_pkb_num;
    pkb_pool->bufsize = bufsize;

    pkb_pool->free_pkt_fifo = rn_gpfifo_create(total_pkb_num, sizeof(rn_pkb_t *));

    for (i = 0; i < total_pkb_num; i++) {
        pkb = (void *)(pkb_pool + 1) + i * one_pkb_size;
        memset(pkb, 0, sizeof(rn_pkb_t));
        pkb->pkb_flag = PN_PKB_FLAG_ALREADY_FREE;
        pkb->bufhead = pkb + 1;
#ifdef RN_CONFIG_PKBPOOL_CHECK
        pkb->pkb_pool = pkb_pool;
        pkb->idx = i;
#endif
        pkb->bufsize = bufsize;
        pkb->cur_off = RN_PKB_OVERHEAD;

        /* insert info free fifo */
        rn_gpfifo_enqueue_p(pkb_pool->free_pkt_fifo, pkb);
    }

    return pkb_pool;
}

int rn_pkb_pool_destroy(rn_pkb_pool_t *pkb_pool)
{
    rn_assert(pkb_pool != NULL);

    rn_gpfifo_destroy(pkb_pool->free_pkt_fifo);

    free(pkb_pool);

    return RN_RETVALUE_OK;
}

rn_pkb_t *rn_pkb_pool_get_pkb_ex(rn_pkb_pool_t *pkb_pool, const char *func, int line)
{
    rn_pkb_t *pkb = rn_gpfifo_dequeue_p(pkb_pool->free_pkt_fifo);

    if (pkb == NULL) {
        return NULL;
    }

    rn_assert(pkb->bufsize == pkb_pool->bufsize);

    rn_assert((pkb->pkb_flag & PN_PKB_FLAG_ALREADY_FREE) == 1);

    pkb->pkb_flag &= ~PN_PKB_FLAG_ALREADY_FREE;
    pkb->cur_off = RN_PKB_OVERHEAD;
    pkb->cur_len = 0;

#ifdef RN_CONFIG_PKBPOOL_CHECK
    pkb->call_func = func;
    pkb->call_linenum = line;
#endif

    return pkb;
}

int rn_pkb_pool_put_pkb(rn_pkb_pool_t *pkb_pool, rn_pkb_t *pkb)
{
#ifdef RN_CONFIG_PKBPOOL_CHECK
    uint32_t one_pkb_size = (sizeof(rn_pkb_t) + pkb_pool->bufsize);
    uint32_t idx = (RN_P2V(pkb) - RN_P2V(pkb_pool + 1)) / one_pkb_size;
    rn_assert(pkb->pkb_pool == pkb_pool);
    rn_assert(idx < pkb_pool->total_pkb_num);
    rn_assert(idx == pkb->idx);
#endif

    rn_assert((pkb->pkb_flag & PN_PKB_FLAG_ALREADY_FREE) == 0);

    pkb->pkb_flag |= PN_PKB_FLAG_ALREADY_FREE;

    return rn_gpfifo_enqueue_p(pkb_pool->free_pkt_fifo, pkb);
}

#ifdef RN_CONFIG_PKBPOOL_CHECK
void rn_pkb_pool_dump(rn_pkb_pool_t *pkb_pool)
{
    uint32_t i, total_free, cnt;
    uint32_t total_pkb_num = pkb_pool->total_pkb_num;
    uint32_t one_pkb_size = (sizeof(rn_pkb_t) + pkb_pool->bufsize);
    uint8_t bm[total_pkb_num];
    rn_pkb_t *pkb;
    rn_transport_frame_head_t *frame_head;

    total_free = RN_GPFIFO_CUR_LEN(pkb_pool->free_pkt_fifo);
    memset(bm, 0, sizeof(bm));
    for (i = 0; i < total_free; i++) {
        pkb = rn_gpfifo_dequeue_p(pkb_pool->free_pkt_fifo);
        bm[pkb->idx] = 1;
        rn_gpfifo_enqueue_p(pkb_pool->free_pkt_fifo, pkb);
    }
    rn_log("pkb pool total %d not free:\n", RN_GPFIFO_CUR_LEFT(pkb_pool->free_pkt_fifo));
    cnt = 0;
    for (i = 0; i < total_pkb_num; i++) {
        if (bm[i] == 1) {
            continue;
        }
        pkb = (void *)(pkb_pool + 1) + i * one_pkb_size;
        frame_head = RN_PKB_HEAD(pkb);
        rn_log("\tidx %d, %s:%d, pkt_type %d, cur_len %d, real_len %d\n",
            pkb->idx, pkb->call_func, pkb->call_linenum, frame_head->type, frame_head->align_len, frame_head->real_len);

        cnt++;
    }
    rn_assert(cnt == RN_GPFIFO_CUR_LEFT(pkb_pool->free_pkt_fifo));
}
#endif

int rn_pkb_recv(rn_pkb_t *pkb, int recv_len, vacc_host_t *vacc_host)
{
    int left = RN_PKB_LEFTSPACE(pkb);
    if (left < recv_len) {
        return RN_RETVALUE_NOENOUGHSPACE;
    }

    rn_assert(recv_len != 0);

    /* do recv */
    recv_len = vacc_host_read(vacc_host, RN_PKB_TAIL(pkb), recv_len);

    if (recv_len >= 0) {
        pkb->cur_len += recv_len;
    }

    return recv_len;
}

int rn_pkb_send(rn_pkb_t *pkb, int send_len, vacc_host_t *vacc_host)
{
    if ((int)pkb->cur_len < send_len) {
        return RN_RETVALUE_NOENOUGHSPACE;
    }

    rn_assert(pkb->cur_len != 0);

    send_len = vacc_host_write(vacc_host, RN_PKB_HEAD(pkb), send_len);
    if (send_len >= 0) {
        /* real send send_len bytes */
        rn_assert((uint32_t)send_len <= pkb->cur_len);
        /* chagen pkb pointer and len */
        pkb->cur_off += send_len;
        pkb->cur_len -= send_len;
    }

    return send_len;
}

int rn_socket_mngr_create(rn_socket_mngr_t *mngr, rn_socket_public_t *socket_list, uint32_t unit_num, uint32_t unit_size, rn_socket_init_cb socket_init, rn_socket_uninit_cb socket_uninit, void *cb_param)
{
    rn_socket_public_t *socket;
    uint32_t i;

    rn_assert(unit_size >= sizeof(rn_socket_public_t));
    rn_assert(mngr != NULL);

    memset(mngr, 0, sizeof(rn_socket_mngr_t));
    mngr->unit_num = unit_num;
    mngr->unit_size = unit_size;
    mngr->free_fifo = rn_gpfifo_create(unit_num, sizeof(rn_socket_public_t *));
    mngr->socket_list = socket_list;
    mngr->socket_init = socket_init;
    mngr->socket_uninit = socket_uninit;
    mngr->cb_param = cb_param;
    rn_initlisthead(&(mngr->listen_list));
    rn_initlisthead(&(mngr->srv_inst_list));
    rn_initlisthead(&(mngr->client_inst_list));

    rn_assert(mngr->free_fifo != NULL);

    for (i = 0; i < unit_num; i++) {
        socket = RN_SOCKET_ENTRY(mngr, i);
        socket->conn_id = i;
        memset(&socket->vacc_host, 0, sizeof(socket->vacc_host));
        socket->vacc_host.sock_fd = -1;
        rn_gpfifo_enqueue_p(mngr->free_fifo, socket);
    }

    return RN_RETVALUE_OK;
}

int rn_socket_mngr_destroy(rn_socket_mngr_t *mngr)
{
    rn_socket_public_t *p, *n;

    /* close all connected socket */
    RN_LISTENTRYWALK_SAVE(p, n, &(mngr->client_inst_list), list_entry) {
        vacc_host_destroy(&(p->vacc_host));
    }
    RN_LISTENTRYWALK_SAVE(p, n, &(mngr->srv_inst_list), list_entry) {
        vacc_host_destroy(&(p->vacc_host));
    }
    /* close all listen socket */
    RN_LISTENTRYWALK_SAVE(p, n, &(mngr->listen_list), list_entry) {
        vacc_host_destroy(&(p->vacc_host));
    }

    return rn_gpfifo_destroy(mngr->free_fifo);;
}

static vacc_host_t* rn_socket_mngr_get(struct _vacc_host *vacc_host, void *opaque)
{
    rn_socket_mngr_t *mngr = (rn_socket_mngr_t *)opaque;
    rn_socket_public_t *socket, *listen_socket = NULL;

    if (vacc_host) {
        listen_socket = RN_GETCONTAINER(vacc_host, rn_socket_public_t, vacc_host);
    }

    socket = rn_gpfifo_dequeue_p(mngr->free_fifo);
    if (socket == NULL) {
        return NULL;
    }

    rn_initlisthead(&(socket->list_entry));

    if (listen_socket) {
        socket->listen_port = listen_socket->listen_port;
    }

    return &(socket->vacc_host);
}

static void rn_socket_mngr_put(struct _vacc_host *vacc_host, void *opaque)
{
    rn_socket_mngr_t *mngr = (rn_socket_mngr_t *)opaque;
    rn_socket_public_t *socket = RN_GETCONTAINER(vacc_host, rn_socket_public_t, vacc_host);

    rn_assert(rn_gpfifo_enqueue_p(mngr->free_fifo, socket) == RN_RETVALUE_OK);
}

static int rn_socket_mngr_init(struct _vacc_host *vacc_host, void *opaque)
{
    rn_socket_mngr_t *mngr = (rn_socket_mngr_t *)opaque;
    rn_socket_public_t *socket = RN_GETCONTAINER(vacc_host, rn_socket_public_t, vacc_host);

    switch (vacc_host->insttype) {
    case VACC_HOST_INSTTYPE_SERVER_LISTENER:
        rn_log("%s listen socket init, conn_id %d, fd %d\n",
            vacc_host->transtype == VACC_HOST_TRANSTYPE_TCP ? "TCP" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDS ? "UDS" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDP ? "UDP" :
            "UNKNOWN",
            socket->conn_id, vacc_host->sock_fd);

        rn_listadd_tail(&(socket->list_entry), &(mngr->listen_list));
        mngr->n_listen++;
        break;
    case VACC_HOST_INSTTYPE_SERVER_INST:
        rn_log("%s server inst connect, conn_id %d, fd %d\n",
            vacc_host->transtype == VACC_HOST_TRANSTYPE_TCP ? "TCP" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDS ? "UDS" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDP ? "UDP" :
            "UNKNOWN",
            socket->conn_id, vacc_host->sock_fd);
        if (vacc_host->transtype == VACC_HOST_TRANSTYPE_TCP) {
            struct in_addr in = vacc_host->u.tcp.cli_addr.sin_addr;
            char ipstr[INET_ADDRSTRLEN];
            unsigned short port;
            port = ntohs(vacc_host->u.tcp.cli_addr.sin_port);
            inet_ntop(AF_INET, &in, ipstr, sizeof(ipstr));
            rn_log("\t\tclient: %s(%d)\n", ipstr, port);
        } else if (vacc_host->transtype == VACC_HOST_TRANSTYPE_UDS) {

        }

        rn_listadd_tail(&(socket->list_entry), &(mngr->srv_inst_list));
        mngr->n_srv_inst++;
        break;
    case VACC_HOST_INSTTYPE_CLIENT_INST:
        rn_log("%s client inst connect, conn_id %d, fd %d\n",
            vacc_host->transtype == VACC_HOST_TRANSTYPE_TCP ? "TCP" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDS ? "UDS" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDP ? "UDP" :
            "UNKNOWN",
            socket->conn_id, vacc_host->sock_fd);

        rn_listadd_tail(&(socket->list_entry), &(mngr->client_inst_list));
        mngr->n_client_inst++;
        break;
    default:
        rn_err("vacc_host_init() unknown inst type %d\n", vacc_host->insttype);
        rn_assert(0);
        return -1;
    }

    if (mngr->socket_init) {
        mngr->socket_init(mngr, socket, mngr->cb_param);
    }

    return 0;
}

static int rn_socket_mngr_uninit(struct _vacc_host *vacc_host, void *opaque)
{
    rn_socket_mngr_t *mngr = (rn_socket_mngr_t *)opaque;
    rn_socket_public_t *socket = RN_GETCONTAINER(vacc_host, rn_socket_public_t, vacc_host);
    int fd = vacc_host->sock_fd;

    if (mngr->socket_uninit) {
        mngr->socket_uninit(mngr, socket, mngr->cb_param);
    }

    /* remove from list */
    rn_listdel(&(socket->list_entry));

    switch (vacc_host->insttype) {
    case VACC_HOST_INSTTYPE_SERVER_LISTENER:
        rn_log("%s listen socket uninit, conn_id %d, fd %d\n",
            vacc_host->transtype == VACC_HOST_TRANSTYPE_TCP ? "TCP" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDS ? "UDS" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDP ? "UDP" :
            "UNKNOWN",
            socket->conn_id, fd);
        mngr->n_listen--;
        break;
    case VACC_HOST_INSTTYPE_SERVER_INST:
        rn_log("%s server inst disconnect, conn_id %d, fd %d\n",
            vacc_host->transtype == VACC_HOST_TRANSTYPE_TCP ? "TCP" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDS ? "UDS" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDP ? "UDP" :
            "UNKNOWN",
            socket->conn_id, fd);
        mngr->n_srv_inst--;
        break;
    case VACC_HOST_INSTTYPE_CLIENT_INST:
        rn_log("%s client inst disconnect, conn_id %d, fd %d\n",
            vacc_host->transtype == VACC_HOST_TRANSTYPE_TCP ? "TCP" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDS ? "UDS" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDP ? "UDP" :
            "UNKNOWN",
            socket->conn_id, fd);
        mngr->n_client_inst--;
        break;
    default:
        rn_err("vacc_host_init() unknown inst type %d\n", vacc_host->insttype);
        rn_assert(0);
        return -1;
    }

    return 0;
}


int rn_socket_mngr_listen_add_ex(rn_socket_mngr_t *mngr, char *ip, uint16_t port, uint32_t sock_bufsize, protocol_abstract_t *proto_abs, vacc_host_cb_recv cb_recv)
{
    rn_socket_public_t *socket;
    vacc_host_t *vacc_host;
    vacc_host_create_param_t param;
    int ret;

    vacc_host = rn_socket_mngr_get(NULL, mngr);
    if (vacc_host == NULL) {
        return RN_RETVALUE_NOENOUGHRES;
    }

    /* bind to ip:port */
    memset(&param, 0, sizeof(param));
    param.transtype = VACC_HOST_TRANSTYPE_TCP;
    param.insttype = VACC_HOST_INSTTYPE_SERVER_LISTENER;
    param.cb_get = rn_socket_mngr_get;
    param.cb_put = rn_socket_mngr_put;
    param.cb_init = rn_socket_mngr_init;
    param.cb_uninit = rn_socket_mngr_uninit;
    param.cb_recv = cb_recv;
    if (proto_abs) {
        param.proto_abs = *proto_abs;
    } else {
        param.proto_abs.enable = 0;
    }
    param.sendbuf_size = sock_bufsize;
    param.recvbuf_size = sock_bufsize;
    param.opaque = mngr;
    strncpy(param.u.tcp.srv_ip, ip, sizeof(param.u.tcp.srv_ip));
    param.u.tcp.srv_port = port;

    ret = vacc_host_create(vacc_host, &param);
    if (ret != VACC_HOST_RET_OK) {
        rn_log("vacc_host_create() return %d\n", ret);
        rn_socket_mngr_put(vacc_host, mngr);
        return RN_RETVALUE_SOCKET_CONNECT_ERR;
    }

    socket = RN_GETCONTAINER(vacc_host, rn_socket_public_t, vacc_host);
    socket->listen_port = port;

    return RN_RETVALUE_OK;
}

int rn_socket_mngr_listen_add(rn_socket_mngr_t *mngr, char *ip, uint16_t port, uint32_t sock_bufsize)
{
    return rn_socket_mngr_listen_add_ex(mngr, ip, port, sock_bufsize, NULL, NULL);
}

int rn_socket_mngr_connect_ex(rn_socket_mngr_t *mngr, char *ip, uint16_t port, uint32_t sock_bufsize, rn_socket_public_t **connected_socket, protocol_abstract_t *proto_abs, vacc_host_cb_recv cb_recv)
{
    rn_socket_public_t *socket;
    vacc_host_t *vacc_host;
    vacc_host_create_param_t param;
    int ret;

    vacc_host = rn_socket_mngr_get(NULL, mngr);
    if (vacc_host == NULL) {
        return RN_RETVALUE_NOENOUGHRES;
    }

    /* connect to ip:port */
    memset(&param, 0, sizeof(param));
    param.transtype = VACC_HOST_TRANSTYPE_TCP;
    param.insttype = VACC_HOST_INSTTYPE_CLIENT_INST;
    param.cb_get = rn_socket_mngr_get;
    param.cb_put = rn_socket_mngr_put;
    param.cb_init = rn_socket_mngr_init;
    param.cb_uninit = rn_socket_mngr_uninit;
    param.cb_recv = cb_recv;
    if (proto_abs) {
        param.proto_abs = *proto_abs;
    } else {
        param.proto_abs.enable = 0;
    }
    param.sendbuf_size = sock_bufsize;
    param.recvbuf_size = sock_bufsize;
    param.opaque = mngr;
    strncpy(param.u.tcp.srv_ip, ip, sizeof(param.u.tcp.srv_ip));
    param.u.tcp.srv_port = port;

    ret = vacc_host_create(vacc_host, &param);
    if (ret != VACC_HOST_RET_OK) {
        rn_log("vacc_host_create() return %d\n", ret);
        rn_socket_mngr_put(vacc_host, mngr);
        return RN_RETVALUE_SOCKET_CONNECT_ERR;
    }

    socket = RN_GETCONTAINER(vacc_host, rn_socket_public_t, vacc_host);
    socket->connect_port = port;

    if (connected_socket) {
        *connected_socket = socket;
    }

    return RN_RETVALUE_OK;
}

int rn_socket_mngr_connect(rn_socket_mngr_t *mngr, char *ip, uint16_t port, uint32_t sock_bufsize, rn_socket_public_t **connected_socket)
{
    return rn_socket_mngr_connect_ex(mngr, ip, port, sock_bufsize, connected_socket, NULL, NULL);
}

void rn_socket_mngr_dump(rn_socket_mngr_t *mngr, rn_socket_mngr_dump_socket dump_fn, void *dump_p)
{
    rn_socket_public_t *p, *n;

    rn_log("n_listen %d, n_srv_inst %d, n_client_inst %d, n_free %d\n",
        mngr->n_listen, mngr->n_srv_inst, mngr->n_client_inst, RN_GPFIFO_CUR_LEN(mngr->free_fifo));
    rn_assert((mngr->n_listen + mngr->n_srv_inst + mngr->n_client_inst + RN_GPFIFO_CUR_LEN(mngr->free_fifo)) == mngr->unit_num);

    /* listen list: */
    if (mngr->n_listen) {
        rn_log("\tlisten list:");
        RN_LISTENTRYWALK_SAVE(p, n, &(mngr->listen_list), list_entry) {
            rn_assert(p->vacc_host.insttype == VACC_HOST_INSTTYPE_SERVER_LISTENER);
            rn_log("\t\t listen port %d\n", p->listen_port);
            if (dump_fn) {
                dump_fn(p, dump_p);
            }
        }
    }
    /* server inst list: */
    if (mngr->n_srv_inst) {
        rn_log("\tserver inst:");
        RN_LISTENTRYWALK_SAVE(p, n, &(mngr->srv_inst_list), list_entry) {
            rn_assert(p->vacc_host.insttype == VACC_HOST_INSTTYPE_SERVER_INST);
            rn_log("\t\tlisten port %d\n", p->listen_port);
            if (dump_fn) {
                dump_fn(p, dump_p);
            }
        }
    }
    /* client inst list: */
    if (mngr->n_client_inst) {
        rn_log("\tclient inst:");
        RN_LISTENTRYWALK_SAVE(p, n, &(mngr->client_inst_list), list_entry) {
            rn_assert(p->vacc_host.insttype == VACC_HOST_INSTTYPE_CLIENT_INST);
            rn_log("\t\tconnect port %d\n", p->connect_port);
            if (dump_fn) {
                dump_fn(p, dump_p);
            }
        }
    }

}


