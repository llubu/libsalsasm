CFLAGS = -Wall -Wextra -Wshadow -Wstrict-overflow -Wsign-compare -Warray-bounds -Wtrigraphs -Wpointer-arith -Wunreachable-code -Wunused-but-set-variable -Wvolatile-register-var -Wwrite-strings -Wstrict-aliasing -DLIBSALSASM_EXPORTS -fPIC -O3 -Os -fomit-frame-pointer -fstrict-aliasing -fstrict-overflow
LDFLAGS = -shared
OBJECTS = salsasm.o decode.o
PYEXT = libsalsasmpy

HEADERS = salsasm.h decode.h salsasm_types.h

all: libsalsasm.so _libsalsasmpy.so

$(PYEXT)_wrap.c: $(HEADERS) $(PYEXT).i
	swig -python $(shell python-config --includes) -I/usr/include -I/usr/local/include $(PYEXT).i

$(PYEXT)_wrap.o: $(PYEXT)_wrap.c $(HEADERS)
	$(CC) -c $(PYEXT)_wrap.c $(CFLAGS) $(shell python-config --cflags) $(shell python-config --includes)

_$(PYEXT).so: $(OBJECTS) $(PYEXT)_wrap.o
	$(CC) -o _$(PYEXT).so $(LDFLAGS) $(shell python-config --ldflags) $(PYEXT)_wrap.o $(OBJECTS) $(shell python-config --libs)

libsalsasm.so: $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(OBJECTS)

$(OBJECTS): $(HEADERS)

.PHONY: clean
clean:
	echo 'Cleaning libsalsasm...'
	rm -f libsalsasm.so *.o
	rm -f _$(PYEXT).so *.os *_wrap.*
	rm -f $(PYEXT).py*
