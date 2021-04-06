## coreSNTP Library

This repository contains the coreSNTP library, a client library to use the Simple Network Time Protocol (SNTP), that is specified in [RFC 4330](https://tools.ietf.org/html/rfc4330), to synchronize client devices with network time.
According to the SNTPv4 specification, "_To an NTP or SNTP server, NTP and SNTP clients are indistinguishable; to an NTP or SNTP client, NTP and SNTP servers are indistinguishable._", thereby, allowing SNTP clients to request time from NTP servers. 

## Reference example


## Building the library

## Building unit tests

### Checkout Unity Submodule
By default, the submodules in this repository are configured with `update=none` in [.gitmodules](.gitmodules), to avoid increasing clone time and disk space usage of other repositories (like [amazon-freertos](https://github.com/aws/amazon-freertos) that submodules this repository).

To build unit tests, the submodule dependency of Unity is required. Use the following command to clone the submodule:
```
git submodule update --checkout --init --recursive --test/unit-test/Unity
```

### Platform Prerequisites

- For running unit tests
    - C89 or later compiler like gcc
    - CMake 3.13.0 or later
- For running the coverage target, gcov is additionally required.

### Steps to build Unit Tests

1. Go to the root directory of this repository. (Make sure that the **Unity** submodule is cloned as described [above](#checkout-unity-submodule).)

1. Create build directory: `mkdir build && cd build`

1. Run *cmake* while inside build directory: `cmake -S ../test`

1. Run this command to build the library and unit tests: `make all`

1. The generated test executables will be present in `build/bin/tests` folder.

1. Run `ctest` to execute all tests and view the test run summary.

## Contributing

See [CONTRIBUTING.md](./.github/CONTRIBUTING.md) for information on contributing.
