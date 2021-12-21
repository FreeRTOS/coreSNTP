var core__sntp__serializer_8h =
[
    [ "SNTP_PACKET_BASE_SIZE", "group__sntp__constants.html#ga9fb0febdb6e2f2dff2e133ef49ce205b", null ],
    [ "SNTP_FRACTION_VALUE_PER_MICROSECOND", "group__sntp__constants.html#ga1baca7c2b918d398acbc5f9412c01ebd", null ],
    [ "SNTP_TIME_AT_UNIX_EPOCH_SECS", "group__sntp__constants.html#gae20ed1490028cf58b01e69af5f2aa635", null ],
    [ "SNTP_TIME_AT_LARGEST_UNIX_TIME_SECS", "group__sntp__constants.html#gabdd46fac2ea38bdacd176c5eb6c8b000", null ],
    [ "UNIX_TIME_SECS_AT_SNTP_ERA_1_SMALLEST_TIME", "group__sntp__constants.html#ga0da33f16640e34e0050d90ba50dade65", null ],
    [ "SNTP_KISS_OF_DEATH_CODE_LENGTH", "group__sntp__constants.html#ga4aa0a62f06b36e48b47e609a6cd0f3ca", null ],
    [ "SNTP_KISS_OF_DEATH_CODE_NONE", "group__sntp__constants.html#ga2f15147fd62ad044b87f8da1cd3f9f7a", null ],
    [ "SntpStatus_t", "group__sntp__enum__types.html#gaef7b22d8008bbfbbc7bbea5a7a30e798", [
      [ "SntpSuccess", "group__sntp__enum__types.html#ggaef7b22d8008bbfbbc7bbea5a7a30e798a8486f9ee1815b43418a9c0478bd8f016", null ],
      [ "SntpErrorBadParameter", "group__sntp__enum__types.html#ggaef7b22d8008bbfbbc7bbea5a7a30e798a1829c0158e4f2630b6806afa4511dfd7", null ],
      [ "SntpRejectedResponse", "group__sntp__enum__types.html#ggaef7b22d8008bbfbbc7bbea5a7a30e798ac03ea3068c8293cf7eea8468d8c12324", null ],
      [ "SntpRejectedResponseChangeServer", "group__sntp__enum__types.html#ggaef7b22d8008bbfbbc7bbea5a7a30e798a771181dbb6df4fb8c21fcb5a160f5ba4", null ],
      [ "SntpRejectedResponseRetryWithBackoff", "group__sntp__enum__types.html#ggaef7b22d8008bbfbbc7bbea5a7a30e798a7c75142ae7cd69ed56d05212ec59a267", null ],
      [ "SntpRejectedResponseOtherCode", "group__sntp__enum__types.html#ggaef7b22d8008bbfbbc7bbea5a7a30e798adcd6c832a7a1c2d4e656538b5e6fefe9", null ],
      [ "SntpErrorBufferTooSmall", "group__sntp__enum__types.html#ggaef7b22d8008bbfbbc7bbea5a7a30e798a23891833ba2ad8634832cbbb9d47bd9c", null ],
      [ "SntpInvalidResponse", "group__sntp__enum__types.html#ggaef7b22d8008bbfbbc7bbea5a7a30e798a4a4f61809052a98c2877cf5035ccc62c", null ],
      [ "SntpZeroPollInterval", "group__sntp__enum__types.html#ggaef7b22d8008bbfbbc7bbea5a7a30e798a2b694f63eaa4d94d08e1bbc80f6fd992", null ],
      [ "SntpErrorTimeNotSupported", "group__sntp__enum__types.html#ggaef7b22d8008bbfbbc7bbea5a7a30e798afba7203b8ee0322999adf1edcca6e0cf", null ],
      [ "SntpErrorDnsFailure", "group__sntp__enum__types.html#ggaef7b22d8008bbfbbc7bbea5a7a30e798a71c91750cf5069fc4223e4aaf0a5d4f0", null ],
      [ "SntpErrorNetworkFailure", "group__sntp__enum__types.html#ggaef7b22d8008bbfbbc7bbea5a7a30e798a6dd0fee9073c6d7c55be89f1bc58b843", null ],
      [ "SntpServerNotAuthenticated", "group__sntp__enum__types.html#ggaef7b22d8008bbfbbc7bbea5a7a30e798acbefde33f8de7f9fac2c31d6a6008397", null ],
      [ "SntpErrorAuthFailure", "group__sntp__enum__types.html#ggaef7b22d8008bbfbbc7bbea5a7a30e798a6db2603ebf3153c9472d3867694aa787", null ],
      [ "SntpErrorSendTimeout", "group__sntp__enum__types.html#ggaef7b22d8008bbfbbc7bbea5a7a30e798a0e41141d4e0b0f1bf945830f7f2c6be9", null ],
      [ "SntpErrorResponseTimeout", "group__sntp__enum__types.html#ggaef7b22d8008bbfbbc7bbea5a7a30e798a379667af0482f651b5630fcc149d9952", null ],
      [ "SntpNoResponseReceived", "group__sntp__enum__types.html#ggaef7b22d8008bbfbbc7bbea5a7a30e798a473ea25a626b0ab1067a9887e49d113e", null ],
      [ "SntpErrorContextNotInitialized", "group__sntp__enum__types.html#ggaef7b22d8008bbfbbc7bbea5a7a30e798afc6ed7e8936aa676762523ba8a308e24", null ]
    ] ],
    [ "SntpLeapSecondInfo_t", "group__sntp__enum__types.html#ga69e2cb17ab4e253491602ccfe48b141f", [
      [ "NoLeapSecond", "group__sntp__enum__types.html#gga69e2cb17ab4e253491602ccfe48b141fab04ffa25889b359ef8ab9a56bbe62fe2", null ],
      [ "LastMinuteHas61Seconds", "group__sntp__enum__types.html#gga69e2cb17ab4e253491602ccfe48b141fa78ff5bb8a6ba0fdafe4fa9aaf001ccbf", null ],
      [ "LastMinuteHas59Seconds", "group__sntp__enum__types.html#gga69e2cb17ab4e253491602ccfe48b141fa207adf1efe110b46607b7520fc05e1a8", null ],
      [ "AlarmServerNotSynchronized", "group__sntp__enum__types.html#gga69e2cb17ab4e253491602ccfe48b141fae2f7a16e8450c21718a098660423f6a9", null ]
    ] ],
    [ "Sntp_SerializeRequest", "core__sntp__serializer_8h.html#ae3aba893e20b6129984062d1b7bf2fa3", null ],
    [ "Sntp_DeserializeResponse", "core__sntp__serializer_8h.html#a3f5dbc349d294809a940ef891cba78fa", null ],
    [ "Sntp_CalculatePollInterval", "core__sntp__serializer_8h.html#a48dc19a11eb31d6077a2ca8964a1c6a9", null ],
    [ "Sntp_ConvertToUnixTime", "core__sntp__serializer_8h.html#ae2e96d3bc60bb30db3107a2bc1d69121", null ]
];