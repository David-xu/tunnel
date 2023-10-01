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