NAME = ft_strace

IDIR = src/include
CC=gcc
CFLAGS=-I$(IDIR) -Wall -Wextra -Werror -fsanitize=address -g3

ODIR=obj
SDIR=src

LIBS=

_DEPS = strace.h syscall.h  syscall_i386_tables.h  syscall_x86_tables.h
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

_OBJ = main.o utils.o syscall.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

all: $(NAME)

$(ODIR)/%.o: $(SDIR)/%.c $(DEPS)
	mkdir -p $(ODIR)
	$(CC) -c -o $@ $< $(CFLAGS)

$(NAME): $(OBJ)
	$(CC) -o $(@) $(OBJ) $(CFLAGS) $(LIBS)

clean:
	rm -rf $(OBJ)
	rm -rf $(ODIR)


fclean: clean
	rm -rf $(NAME)

re: fclean all

.PHONY: all fclean clean re test