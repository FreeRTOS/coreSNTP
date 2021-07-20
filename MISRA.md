# MISRA Compliance

The coreSNTP library files conform to the [MISRA C:2012](https://www.misra.org.uk)
guidelines, with some noted exceptions. Compliance is checked with Coverity static analysis.
Deviations from the MISRA standard are listed below:

### Ignored by [Coverity Configuration](https://github.com/aws/aws-iot-device-sdk-embedded-C/blob/main/tools/coverity/misra.config)
| Deviation | Category | Justification |
| :-: | :-: | :-: |
| Directive 4.9 | Advisory | Allow inclusion of function like macros. The `assert` macro is used throughout the library for parameter validation, and logging is done using function like macros. |
| Rule 2.4 | Advisory | Allow unused tags. Some compilers warn if types are not tagged. |
| Rule 2.5 | Advisory | Allow unused macros. Library headers may define macros intended for the application's use, but are not used by a specific file. |
| Rule 3.1 | Required | Allow nested comments. C++ style `//` comments are used in example code within Doxygen documentation blocks. |
| Rule 11.5 | Advisory | Allow casts from `void *`. The library casts the byte array information received network to a `SntpPacket_t *` for parsing SNTP packet. |

### Flagged by Coverity
| Deviation | Category | Justification |
| :-: | :-: | :-: |
| Rule 8.7 | Advisory | API functions are not used by the library outside of the files they are defined; however, they must be externally visible in order to be used by an application. |

### Suppressed with Coverity Comments
*None.*
