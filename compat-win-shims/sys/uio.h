/* Windows shim: redirect a POSIX header to the MOOR compat layer.
 * Added to the include path only on Windows (-Icompat/win), so sources that
 * include POSIX socket headers unconditionally compile unmodified. */
#include "moor/compat_win.h"
