# CS332 - Reliable File Transferral over UDP

This C++ project implementing a reliable file transferal protocol over UDP was written as an assignment for CS332: Advanced Computer Networking.

To build, run `build.sh`, and executables will be placed in `cmake-build-release`.

There are 4 separate executables:
- `rft_sender <address> <port> <file path>`: Send a file to another system.
- `rft_receiver <port> <file path>`: Wait for a file to be sent, and write it to the given file path.
- `rft_sender_verbose <address> <port> <file path>`: Same as `rft_sender`, but more verbosely.
- `rft_receiver_verbose <port> <file path>`: Same as `rft_receiver`, but more verbosely.

(Apologies for the lack of a `-v` flag on `rft_sender` and `rft_receiver` to configure verbosity rather than the separate executables; I didn't have time to change that.)
