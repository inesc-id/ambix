CC = gcc
CFLAGS = -I. -I./api
DEPS = api/ambix.h
OBJ = range_monitoring_test.o api/ambix.o

%.o: %.c $(DEPS)
    $(CC) -c -o $@ $< $(CFLAGS)

range_monitoring_test: $(OBJ)
    $(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean

clean:
    rm -f *.o range_monitoring_test