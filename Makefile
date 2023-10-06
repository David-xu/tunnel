APP=fgfw

#Makefile
CC  = gcc

# base source
SUBMOD = .

SRCS := $(foreach n, $(SUBMOD), $(wildcard $(n)/*.c))
OBJS := $(patsubst %.c, %.o, $(SRCS))

OBJECTPATH=$(shell pwd)

# include header
CFLAGS += $(foreach n, $(SUBMOD), $(addprefix -I, $(n)))

CFLAGS += -g -W -Wall -Wno-unused-parameter -Wno-format-truncation -D_GNU_SOURCE
CFLAGS += -Wno-deprecated-declarations

# -lpci: fpga_access use this library, add it
LDFLAGS += -pthread -lm -lssl -lcrypto

all: $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -g -o $(APP)

$(OBJS) : $(SRCS)

.PHONY : clean
clean:
	$(RM) $(OBJS) $(APP)
