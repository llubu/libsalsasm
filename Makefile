CFLAGS = -Wall -Wextra -Wshadow -Wstrict-overflow -Wsign-compare -Warray-bounds -Wtrigraphs -Wpointer-arith -Wunreachable-code -Wunused-but-set-variable -Wvolatile-register-var -Wwrite-strings -Wstrict-aliasing -DLIBSALSASM_EXPORTS -fPIC -O3 -Os -fomit-frame-pointer -fstrict-aliasing -fstrict-overflow
LDFLAGS = -shared
OBJECTS = salsasm.o decode.o

HEADERS = salsasm.h decode.h salsasm_types.h

libsalsasm.so: $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(OBJECTS)

$(OBJECTS): $(HEADERS)

.PHONY: clean
clean:
	@echo 'Cleaning libsalsasm...'
	@rm -f libsalsasm.so *.o
