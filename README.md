# Flic 2 - C module

This module implements the Flic 2 protocol in a platform-independent way.
The module uses a `Flic2Button` object which represents one single Flic 2 button.
One `Flic2Button` shall exist for every Flic 2 button.

BLE scanning and connection setup are not included in this module and must be handled externally.

See the [Flic 2 Protocol Specification](https://github.com/50ButtonsEach/flic2-documentation) for instructions how to identify advertising buttons,
how to connect and which two GATT characteristics to use for communication.

The system must provide a steady clock (called `steady_clock`), which represents monotonic time
since some undefined starting point. This clock shall not be affected by discontinuous jumps in the system time
(e.g. if the administrator manually changes the clock). On Linux, `CLOCK_MONOTONIC` can be used for this purpose.
On embedded systems usually an RTC that starts when the system boots can be used. Ability to wait until
a given time point requested by this module must be implemented.

The system should also provide a system clock (wall-clock), which represents real time (UNIX timestamp).
On Linux `CLOCK_REALTIME` can be used for this purpose. Its purpose is to store timestamps for name,
battery measurement time and when to check for new firmware. If no system clock is available,
use 0 as the current time whenever requested to provide the current time.

The granularity of the time should be at least second precision, but millisecond precision or better is desired.
If multiple function calls are to be made in sequence, the same time can be reused for all calls.

If a Flic 2 pairing should persist across reboots or restarts of the application,
a database must be implemented that can add, update and delete a button.

The system must provide a cryptographically secure random number generator that can generate at least 16 bytes.

When the application starts or when a new button shall be intialized, `flic2_init` shall be called for every button.
For every newly established BLE connection and after GATT MTU Exchange (if available) has taken place, `flic2_start` shall be called.
Instead of utilizing callbacks, this module emits events that are fetched using the `flic2_get_next_event` function.
The idea is that after calling one or more functions (except for `flic2_init`), `flic2_get_next_event` shall be called in a loop until
no more events are returned.

The full documentation can be found in the flic.h header file.

# Licensing

This module is released under the GPLv3 license, which allows evaluation as well as for use in GPLv3 licensed open source projects. To request a commercial license, please contact us at https://flic.io/business#contact.
