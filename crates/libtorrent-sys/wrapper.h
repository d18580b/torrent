/* bindgen entry point. Order matters: alert_union.h provides the full
 * definition of lt_alert_union, libtorrent_shim.h only forward-declares it.
 * Including alert_union.h first gives bindgen the complete type, then the
 * function declarations in libtorrent_shim.h see it as a known type. */
#include "alert_union.h"
#include "libtorrent_shim.h"
