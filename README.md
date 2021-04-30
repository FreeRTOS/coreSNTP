## coreSNTP Library

**Note:** This library is under development.

This repository contains the coreSNTP library, a client library to use Simple Network Time Protocol (SNTP) to synchronize device clocks with internet time. This library implements the SNTPv4 specification defined in [RFC 4330](https://tools.ietf.org/html/rfc4330).

An SNTP client can request time from both NTP and SNTP servers. According to the SNTPv4 specification, "_To an NTP or SNTP server, NTP and SNTP clients are indistinguishable; to an NTP or SNTP client, NTP and SNTP servers are indistinguishable._", thereby, allowing SNTP clients to request time from NTP servers. 

## Cloning this repository
This repo uses [Git Submodules](https://git-scm.com/book/en/v2/Git-Tools-Submodules) to bring in dependent components.

To clone using HTTPS:
```
git clone https://github.com/FreeRTOS/coreSNTP.git --recurse-submodules
```
Using SSH:
```
git clone git@github.com:FreeRTOS/coreSNTP.git --recurse-submodules
```

If you have downloaded the repo without using the `--recurse-submodules` argument, you need to run:
```
git submodule update --init --recursive
```

## Building the library

You can build the coreSNTP source files that are in the [source](source/) directory, and add [source/include](source/include) to your compiler's include path.

If using CMake, the [coreSntpFilePaths.cmake](coreSntpFilePaths.cmake) file contains the above information of the source files and the header include path from this repository.

## Building Unit Tests

### Checkout CMock Submodule

To build unit tests, the submodule dependency of CMock is required. Use the following command to clone the submodule:
```
git submodule update --checkout --init --recursive test/unit-test/CMock
```

### Unit Test Platform Prerequisites

- For running unit tests
    - **C90 compiler** like gcc
    - **CMake 3.13.0 or later**
    - **Ruby 2.0.0 or later** is additionally required for the CMock test framework (that we use).
- For running the coverage target, **gcov** and **lcov** are additionally required.

### Steps to build **Unit Tests**

1. Go to the root directory of this repository. (Make sure that the **CMock** submodule is cloned as described [above](#checkout-cmock-submodule))

1. Run the *cmake* command: `cmake -S test -B build`

1. Run this command to build the library and unit tests: `make -C build all`

1. The generated test executables will be present in `build/bin/tests` folder.

1. Run `cd build && ctest` to execute all tests and view the test run summary.

## Contributing

See [CONTRIBUTING.md](./.github/CONTRIBUTING.md) for information on contributing.

## License

This library is licensed under the MIT License. See the [LICENSE](LICENSE) file.
