/* Fixed hosted post-failure observation; no caller-selected path or operation. */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <windows.h>
#include "registry-loader-path.h"

#if PY_MAJOR_VERSION != 3 || PY_MINOR_VERSION != 11 || defined(Py_DEBUG) || !defined(_WIN64)
#error Unsupported fixed loader Python ABI
#endif

static struct PyModuleDef definition = {
    PyModuleDef_HEAD_INIT, "_registry_loader", NULL, -1, NULL, NULL, NULL, NULL, NULL
};

static int constant(PyObject *module, const char *name, unsigned long value)
{
    PyObject *number = PyLong_FromUnsignedLong(value);
    if (number == NULL) return -1;
    if (PyModule_AddObject(module, name, number) < 0) {
        Py_DECREF(number);
        return -1;
    }
    return 0;
}

PyMODINIT_FUNC PyInit__registry_loader(void)
{
    HMODULE loaded = LoadLibraryExW(registry_loader_path, NULL, 0x1100);
    DWORD error = 0, release_error = 0;
    BOOL released = FALSE;
    if (loaded == NULL) error = GetLastError();
    else {
        released = FreeLibrary(loaded);
        if (!released) release_error = GetLastError();
    }
    /* A failed BOOL with zero error must never mimic successful release. */
    if ((loaded == NULL && error == 0) || (loaded != NULL && !released && release_error == 0)) {
        PyErr_SetString(PyExc_RuntimeError, "fixed loader result is unqualified");
        return NULL;
    }
    PyObject *module = PyModule_Create(&definition);
    if (module == NULL) return NULL;
    if (constant(module, "loaded", loaded != NULL) < 0 ||
        constant(module, "load_error", error) < 0 ||
        constant(module, "release_error", release_error) < 0 ||
        constant(module, "version", 1) < 0) {
        Py_DECREF(module);
        return NULL;
    }
    return module;
}
