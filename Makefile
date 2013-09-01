CFLAGS = -Wall -Wextra -DLIBSALSASM_EXPORTS -fPIC
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
