libsalsasm_HEADERS := salsasm.h decode.h codegen.h salsasm_types.h
libsalsasm_SOURCES := salsasm.c decode.c

$(eval $(call CREATE_MODULE,libsalsasm,LIB))
