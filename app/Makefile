# m46ecli Makefile
CC     = gcc
CFLAGS = -O2 -g
TARGET = m46ecli
OBJS   = m46e_cli.o m46e_cli_call.o m46e_cli_chk.o m46e_pr_cmd.o m46e_pmtu.o m46e_cmd.o m46e_cli_tbl.o m46e_ns_cmd.o

.SUFFIXES: .c .o

.PHONY: all
all: depend $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $^

.c.o:
	$(CC) $(CFLAGS) -c $<

.PHONY: clean
clean:
	$(RM) $(OBJS) $(TARGET) depend.inc *~

.PHONY: depend
depend: $(OBJS:.o=.c)
	-@ $(RM) depend.inc
	-@ for i in $^; do cpp -MM $$i | sed "s/\ [_a-zA-Z0-9][_a-zA-Z0-9]*\.c//g" >> depend.inc; done

-include depend.inc
