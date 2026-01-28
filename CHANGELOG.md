# Changelog for coreSNTP Library

## v2.0.0 (January 2026)

### Changes
- [#113](https://github.com/FreeRTOS/coreSNTP/pull/113) Add write permissions to doxygen generation workflow on main.
- [#112](https://github.com/FreeRTOS/coreSNTP/pull/112) Add migration guide for v2.0.0.
- [#111](https://github.com/FreeRTOS/coreSNTP/pull/111) Update manifest.yml.
- [#110](https://github.com/FreeRTOS/coreSNTP/pull/110) Add CMakeLists.txt.
- [#109](https://github.com/FreeRTOS/coreSNTP/pull/109) Remove version numbers and add library version macro.
- [#107](https://github.com/FreeRTOS/coreSNTP/pull/107) Remove formatting bot workflow.
- [#105](https://github.com/FreeRTOS/coreSNTP/pull/105) Refine Sntp_ConvertToUnixTime.
- [#104](https://github.com/FreeRTOS/coreSNTP/pull/104) Fix Year 2038 Problem in Sntp_ConvertToUnixTime.
- [#102](https://github.com/FreeRTOS/coreSNTP/pull/102) Update release.yml as per security guideline.
- [#101](https://github.com/FreeRTOS/coreSNTP/pull/101) Remove unwanted comment for return value of SntpGetTime_t.
- [#99](https://github.com/FreeRTOS/coreSNTP/pull/99) Replace Synopsys link with blackduck one to solve link error.
- [#98](https://github.com/FreeRTOS/coreSNTP/pull/98) Adjust proof tooling to support CBMC v6.
- [#97](https://github.com/FreeRTOS/coreSNTP/pull/97) Update LTS 202406 information.

## v1.3.1 (June 2024)

### Changes
 - Fix doxygen deployment on Github.

## v1.3.0 (May 2024)

### Changes
 - [#85](https://github.com/FreeRTOS/coreSNTP/pull/85) Fix MISRA C 2012 deviations.
 - [#83](https://github.com/FreeRTOS/coreSNTP/pull/83) Include all SntpStatus_t values in Sntp_StatusToStr.
 - [#81](https://github.com/FreeRTOS/coreSNTP/pull/81) Logging Print Formatter Fix.

## v1.2.0 (October 2022)

### Changes
 - [#63](https://github.com/FreeRTOS/coreSNTP/pull/63) Move user config includes from header to C files.
 - [#61](https://github.com/FreeRTOS/coreSNTP/pull/61) MISRA C:2012 compliance update
 - [#60](https://github.com/FreeRTOS/coreSNTP/pull/60) Update CBMC Starter kit
 - [#57](https://github.com/FreeRTOS/coreSNTP/pull/57) Loop Invariant Update

## v1.1.0 (November 2021)

### Changes
 - [#52](https://github.com/FreeRTOS/coreSNTP/pull/52) Change license from MIT-0 to MIT.
 - [#47](https://github.com/FreeRTOS/coreSNTP/pull/47) Update doxygen version used for documentation to 1.9.2.

## v1.0.0 (July 2021)

This is the first release of an coreSNTP client library in this repository.

This library implements an SNTP client for the [SNTPv4 specification](https://tools.ietf.org/html/rfc4330). It is optimized for resource-constrained devices, and does not allocate any memory.
