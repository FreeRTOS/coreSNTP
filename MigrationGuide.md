## coreSNTP version >=v2.0.0 Migration Guide

With coreSNTP versions >=v2.0.0, there are breaking changes that need to be addressed when upgrading.

### Breaking Changes

* The `Sntp_ConvertToUnixTime` function now uses `uint32_t *` instead of `UnixTime_t *` for the Unix time seconds parameter. This change was made because:
  - A `uint32_t` Unix timestamp can represent dates until February 7, 2106 06:28:15 UTC
  - Beyond this date, we cannot differentiate between NTP era 0 and era 1 timestamps
  - This provides a more accurate representation of the library's actual capabilities

Thus, the signature of `Sntp_ConvertToUnixTime` changed from:
```c
SntpStatus_t Sntp_ConvertToUnixTime( const SntpTimestamp_t * pSntpTime,
                                      UnixTime_t * pUnixTimeSecs,
                                      uint32_t * pUnixTimeMicrosecs );
```

to:

```c
SntpStatus_t Sntp_ConvertToUnixTime( const SntpTimestamp_t * pSntpTime,
                                      uint32_t * pUnixTimeSecs,
                                      uint32_t * pUnixTimeMicrosecs );
```

To migrate, update any code that uses `UnixTime_t` for storing the Unix time seconds value to use `uint32_t` instead.

**Old Code Snippet**:
```c
SntpTimestamp_t sntpTime;
UnixTime_t unixTimeSecs;
uint32_t unixTimeMicrosecs;
SntpStatus_t status;

// Assume sntpTime has been populated from an SNTP response

status = Sntp_ConvertToUnixTime( &sntpTime, &unixTimeSecs, &unixTimeMicrosecs );

if( status == SntpSuccess )
{
    // Use the Unix time
    printf( "Unix time: %llu.%06u\n", ( unsigned long long ) unixTimeSecs, unixTimeMicrosecs );
}
```

**New Code Snippet**:
```c
SntpTimestamp_t sntpTime;
uint32_t unixTimeSecs;
uint32_t unixTimeMicrosecs;
SntpStatus_t status;

// Assume sntpTime has been populated from an SNTP response

status = Sntp_ConvertToUnixTime( &sntpTime, &unixTimeSecs, &unixTimeMicrosecs );

if( status == SntpSuccess )
{
    // Use the Unix time
    printf( "Unix time: %u.%06u\n", unixTimeSecs, unixTimeMicrosecs );
}
```

### Additional Changes

* **Year 2038 Problem Fixed**: The library now properly handles timestamps beyond January 19, 2038 03:14:07 UTC (the traditional Unix timestamp overflow point for 32-bit signed integers). The library uses unsigned 32-bit integers and can represent dates until February 7, 2106.

* **Improved Time Conversion**: The `Sntp_ConvertToUnixTime` function now includes proper overflow and underflow checking to ensure time conversions are handled safely.
