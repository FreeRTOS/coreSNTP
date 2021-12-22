var group__sntp__struct__types =
[
    [ "SntpServerInfo_t", "struct_sntp_server_info__t.html", [
      [ "pServerName", "struct_sntp_server_info__t.html#a3ac6b772408c867c83bc278aebbfe192", null ],
      [ "serverNameLen", "struct_sntp_server_info__t.html#a1c2da66f537d838bb5624ece9042771d", null ],
      [ "port", "struct_sntp_server_info__t.html#a2c89b20c6fa40631a1d70000a39a3df5", null ]
    ] ],
    [ "UdpTransportInterface_t", "struct_udp_transport_interface__t.html", [
      [ "pUserContext", "struct_udp_transport_interface__t.html#ad47cd85071e0815a75f749710096190e", null ],
      [ "sendTo", "struct_udp_transport_interface__t.html#a332883a73a30ab9fb229ff24f305f0b5", null ],
      [ "recvFrom", "struct_udp_transport_interface__t.html#a30f8e36e611f4d510d4ffa20b19d3cb4", null ]
    ] ],
    [ "SntpAuthenticationInterface_t", "struct_sntp_authentication_interface__t.html", [
      [ "pAuthContext", "struct_sntp_authentication_interface__t.html#a4ed258485fc69f19f148f19e6aa1bcf2", null ],
      [ "generateClientAuth", "struct_sntp_authentication_interface__t.html#a347198d179e4582719ba1509a50f3697", null ],
      [ "validateServerAuth", "struct_sntp_authentication_interface__t.html#ae345f04269ea310ee7b97ed27b48a2a2", null ]
    ] ],
    [ "SntpContext_t", "struct_sntp_context__t.html", [
      [ "pTimeServers", "struct_sntp_context__t.html#aa54faa689895cbe319ba7c63f8444311", null ],
      [ "numOfServers", "struct_sntp_context__t.html#a7b36f6cb0f770aaabf410600e93b6157", null ],
      [ "currentServerIndex", "struct_sntp_context__t.html#ad476e3a1f24c35d7b22be3181b3a09c5", null ],
      [ "pNetworkBuffer", "struct_sntp_context__t.html#a4c7c642226557c832bcb692a7adeb113", null ],
      [ "bufferSize", "struct_sntp_context__t.html#ae85a52c6c617a51b75099e1bd46ffd54", null ],
      [ "resolveDnsFunc", "struct_sntp_context__t.html#a360b87be7ee57aac6f009ce97ec887b6", null ],
      [ "getTimeFunc", "struct_sntp_context__t.html#ab613eb473896ed8fa98a1a91e5a8a028", null ],
      [ "setTimeFunc", "struct_sntp_context__t.html#a73ab563c2942206a9f8154204c22288f", null ],
      [ "networkIntf", "struct_sntp_context__t.html#a01f1697d75c66c572c3f45e461313724", null ],
      [ "authIntf", "struct_sntp_context__t.html#ac8f3cb93edc50b7a242cd9144fe7d31f", null ],
      [ "currentServerAddr", "struct_sntp_context__t.html#a7bf778e376b5baa01b0bbef3a5be1bb9", null ],
      [ "lastRequestTime", "struct_sntp_context__t.html#a18298d0f5921ca919d99ea72303d91a5", null ],
      [ "sntpPacketSize", "struct_sntp_context__t.html#ab9fe8b67de98aee832ea33235881eb59", null ],
      [ "responseTimeoutMs", "struct_sntp_context__t.html#a208187bbe54b276d63c914be74eb6262", null ]
    ] ],
    [ "SntpTimestamp_t", "struct_sntp_timestamp__t.html", [
      [ "seconds", "struct_sntp_timestamp__t.html#a747c002d1a619beef24932a2703a579c", null ],
      [ "fractions", "struct_sntp_timestamp__t.html#a31fd5b20451f4c23534322b4eaa8d29f", null ]
    ] ],
    [ "SntpResponseData_t", "struct_sntp_response_data__t.html", [
      [ "serverTime", "struct_sntp_response_data__t.html#a33590fd195287b96659903f5c81da0ad", null ],
      [ "leapSecondType", "struct_sntp_response_data__t.html#a7896b39b307d69f1a5a93ef62fbbda9a", null ],
      [ "rejectedResponseCode", "struct_sntp_response_data__t.html#a6ce5c37cac67aea775f9578fa4d95e1a", null ],
      [ "clockOffsetMs", "struct_sntp_response_data__t.html#a98acec60dff84cb131b4a678ac4ca498", null ]
    ] ],
    [ "NetworkContext_t", "group__sntp__struct__types.html#ga7769e434e7811caed8cd6fd7f9ec26ec", null ],
    [ "SntpAuthContext_t", "group__sntp__struct__types.html#gaff243b342eebc2622fbb493d08663133", null ]
];