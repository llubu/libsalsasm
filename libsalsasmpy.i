%module(directors="1") libsalsasmpy
%{
#define SWIG_FILE_WITH_INIT
#include "salsasm.h"
%}

%feature("callback") Callback;

%include "stdint.i"
%include "salsasm.h"
