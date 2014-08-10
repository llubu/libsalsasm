libsalsasm_HEADERS := salsasm.h decode.h codegen.h salsasm_types.h
libsalsasm_SOURCES := salsasm.c decode.c

libsalsasm_CFLAGS += -DLIBSALSASM_EXPORTS

$(eval $(call CREATE_MODULE,libsalsasm,LIB))
