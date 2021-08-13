# Pete

A friendly wrapper around the Linux `ptrace(2)` syscall.

## Requirements

The current minimum supported OS and compiler versions are:

- Linux 4.8
- rustc 1.46.0

Continuous testing is only run for `x86_64-unknown-linux-gnu`.

Support for earlier Linux versions is possible, but low priority. Eventually, we would
like to support any platform that provides `ptrace(2)`.

## Summary

The `ptrace(2)` interface entails interpreting a series of `wait(2)` statuses. The context used to
interpret a status includes the attach options set on each tracee, previously-seen stops, recent
ptrace requests, and in some cases, extra event data that must be queried using additional ptrace
calls.

Pete is meant to instead permit reasoning directly about ptrace-stops, as described in the manual.
We hide the lowest-level contextual bookkeeping required to disambiguate ptrace-stops. Whenever we
can, we avoid extraneous ptrace calls, deferring to downstream tracers implemented on top of the
library. For example, Pete can distinguish a syscall-enter-stop and syscall-exit-stop, but does not
_automatically_ query register state to identify the specific syscall.

## License

Pete is licensed under the [ISC License](./LICENSE).

## Contributing

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
`pete` by you, shall be licensed as ISC, without any additional terms or conditions.
