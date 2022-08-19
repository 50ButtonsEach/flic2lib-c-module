/**
 *  Flic 2 C module
 *
 *  Copyright (C) 2022 Shortcut Labs AB
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef FLIC2_PACKETS_H
#define FLIC2_PACKETS_H

#include <stdint.h>

#ifdef _MSC_VER
#pragma pack(push, 1)
#ifndef PACKED
#define PACKED
#endif
#else
#ifndef PACKED
#define PACKED __attribute__ ((packed))
#endif
#endif

enum OpcodeToFlic {
    OPCODE_TO_FLIC_FULL_VERIFY_REQUEST_1,
    OPCODE_TO_FLIC_FULL_VERIFY_REQUEST_2_WITH_APP_TOKEN,
    OPCODE_TO_FLIC_FULL_VERIFY_REQUEST_2_WITHOUT_APP_TOKEN,
    OPCODE_TO_FLIC_FULL_VERIFY_ABORT_IND,
    OPCODE_TO_FLIC_TEST_IF_REALLY_UNPAIRED_REQUEST,
    OPCODE_TO_FLIC_QUICK_VERIFY_REQUEST,
    OPCODE_TO_FLIC_FORCE_BT_DISCONNECT_IND,
    OPCODE_TO_FLIC_BLE_SECURITY_REQUEST_IND,
    OPCODE_TO_FLIC_GET_FIRMWARE_VERSION_REQUEST,
    
    OPCODE_TO_FLIC_DISCONNECT_VERIFIED_LINK_IND,
    OPCODE_TO_FLIC_SET_NAME_REQUEST,
    OPCODE_TO_FLIC_GET_NAME_REQUEST,
    OPCODE_TO_FLIC_SET_CONNECTION_PARAMETERS_IND,
    OPCODE_TO_FLIC_START_API_TIMER_IND,
    OPCODE_TO_FLIC_PING_RESPONSE,
    OPCODE_TO_FLIC_INIT_BUTTON_EVENTS_REQUEST,
    OPCODE_TO_FLIC_ACK_BUTTON_EVENTS_IND,
    OPCODE_TO_FLIC_START_FIRMWARE_UPDATE_REQUEST,
    OPCODE_TO_FLIC_FIRMWARE_UPDATE_DATA_IND,
    OPCODE_TO_FLIC_SET_AUTO_DISCONNECT_TIME_IND,
    OPCODE_TO_FLIC_GET_BATTERY_LEVEL_REQUEST,

    OPCODE_TO_FLIC_SET_HID_STATUS_REQUEST,
    OPCODE_TO_FLIC_HID_NOTIFICATION,
    OPCODE_TO_FLIC_INIT_BUTTON_EVENTS_LIGHT_REQUEST,
    OPCODE_TO_FLIC_FACTORY_RESET_REQUEST,
    OPCODE_TO_FLIC_GET_CURRENT_TIME_REQUEST,
    OPCODE_TO_FLIC_GET_DEVICE_ID_REQUEST,
    OPCODE_TO_FLIC_SET_ADV_PARAMETERS_REQUEST,
};

enum OpcodeFromFlic {
    OPCODE_FROM_FLIC_FULL_VERIFY_RESPONSE_1,
    OPCODE_FROM_FLIC_FULL_VERIFY_RESPONSE_2,
    OPCODE_FROM_FLIC_NO_LOGICAL_CONNECTION_SLOTS_IND,
    OPCODE_FROM_FLIC_FULL_VERIFY_FAIL_RESPONSE,
    OPCODE_FROM_FLIC_TEST_IF_REALLY_UNPAIRED_RESPONSE,
    OPCODE_FROM_FLIC_GET_FIRMWARE_VERSION_RESPONSE,
    OPCODE_FROM_FLIC_QUICK_VERIFY_NEGATIVE_RESPONSE,
    OPCODE_FROM_FLIC_PAIRING_FINISHED_IND,
    
    OPCODE_FROM_FLIC_QUICK_VERIFY_RESPONSE,
    OPCODE_FROM_FLIC_DISCONNECTED_VERIFIED_LINK_IND,
    
    OPCODE_FROM_FLIC_INIT_BUTTON_EVENTS_RESPONSE_WITH_BOOT_ID,
    OPCODE_FROM_FLIC_INIT_BUTTON_EVENTS_RESPONSE_WITHOUT_BOOT_ID,
    OPCODE_FROM_FLIC_BUTTON_EVENT_NOTIFICATION,
    OPCODE_FROM_FLIC_API_TIMER_NOTIFICATION,
    OPCODE_FROM_FLIC_NAME_UPDATED_NOTIFICATION,
    OPCODE_FROM_FLIC_PING_REQUEST,
    OPCODE_FROM_FLIC_GET_NAME_RESPONSE,
    OPCODE_FROM_FLIC_SET_NAME_RESPONSE,
    OPCODE_FROM_FLIC_START_FIRMWARE_UPDATE_RESPONSE,
    OPCODE_FROM_FLIC_FIRMWARE_UPDATE_NOTIFICATION,
    OPCODE_FROM_FLIC_GET_BATTERY_LEVEL_RESPONSE,

    OPCODE_FROM_FLIC_SERVICES_CHANGED_CONFIRMED_IND,
    OPCODE_FROM_FLIC_FACTORY_RESET_RESPONSE,
    OPCODE_FROM_FLIC_GET_CURRENT_TIME_RESPONSE,
    OPCODE_FROM_FLIC_GET_DEVICE_ID_RESPONSE,
    OPCODE_FROM_FLIC_SET_ADV_PARAMETERS_RESPONSE,
};

enum DisconnectLogicalConnectionReason {
    DISCONNECT_LOGICAL_CONNECTION_REASON_PING_TIMEOUT,
    DISCONNECT_LOGICAL_CONNECTION_REASON_INVALID_SIGNATURE,
    DISCONNECT_LOGICAL_CONNECTION_REASON_STARTED_NEW_WITH_SAME_PAIRING_IDENTIFIER,
    DISCONNECT_LOGICAL_CONNECTION_REASON_BY_USER
};

enum FullVerifyFailReason {
    FULL_VERIFY_FAIL_REASON_INVALID_VERIFIER,
    FULL_VERIFY_FAIL_REASON_NOT_IN_PUBLIC_MODE,
};

struct FullVerifyRequest1 {
    uint8_t opcode;
    uint32_t tmp_id;
} PACKED;

struct FullVerifyResponse1 {
    uint8_t opcode;
    uint32_t tmp_id;
    uint8_t signature[64];
    uint8_t address[6];
    uint8_t address_type;
    uint8_t ecdh_public_key[32];
    uint8_t random_bytes[8];
    uint8_t link_is_encrypted: 1;
    uint8_t is_in_public_mode: 1;
    uint8_t has_bond_info: 1;
    uint8_t padding: 5;
} PACKED;

struct FullVerifyRequest2WithoutAppToken {
    uint8_t opcode;
    uint8_t ecdh_public_key[32];
    uint8_t random_bytes[8];
    uint8_t signature_variant: 3;
    uint8_t encryption_variant: 3;
    uint8_t must_validate_app_token: 1;
    uint8_t padding: 1;
    uint8_t verifier[16];
} PACKED;

struct FullVerifyRequest2WithAppToken {
    uint8_t opcode;
    uint8_t ecdh_public_key[32];
    uint8_t random_bytes[8];
    uint8_t signature_variant: 3;
    uint8_t encryption_variant: 3;
    uint8_t must_validate_app_token: 1;
    uint8_t padding: 1;
    uint8_t encrypted_app_token[16];
    uint8_t verifier[16];
} PACKED;

struct FullVerifyResponse2 {
    uint8_t opcode;
    uint8_t app_credentials_match: 1;
    uint8_t cares_about_app_credentials: 1;
    uint8_t padding: 6;
    uint8_t button_uuid[16];
    uint8_t name_len;
    char name[23];
    uint32_t firmware_version;
    uint16_t battery_level;
    char serial_number[11];
} PACKED;

struct FullVerifyFailResponse {
    uint8_t opcode;
    uint8_t reason;
} PACKED;

struct TestIfReallyUnpairedRequest {
    uint8_t opcode;
    uint8_t ecdh_public_key[32];
    uint8_t random_bytes[8];
    uint32_t pairing_identifier;
    uint8_t pairing_token[16];
} PACKED;

struct TestIfReallyUnpairedResponse {
    uint8_t opcode;
    uint8_t result[16];
} PACKED;

struct NoLogicalConnectionSlotsInd {
    uint8_t opcode;
    uint32_t tmp_ids[];
} PACKED;

struct DisconnectedVerifiedLinkInd {
    uint8_t opcode;
    uint8_t reason;
} PACKED;

struct QuickVerifyRequest {
    uint8_t opcode;
    uint8_t random_client_bytes[7];
    uint8_t signature_variant: 3;
    uint8_t encryption_variant: 3;
    uint8_t padding: 2;
    uint32_t tmp_id;
    uint32_t pairing_identifier;
} PACKED;

struct QuickVerifyResponse {
    uint8_t opcode;
    uint8_t random_button_bytes[8];
    uint32_t tmp_id;
    uint8_t link_is_encrypted: 1;
    uint8_t has_bond_info: 1;
    uint8_t padding: 6;
} PACKED;

struct QuickVerifyNegativeResponse {
    uint8_t opcode;
    uint32_t tmp_id;
} PACKED;

struct PairingFinishedInd {
    uint8_t opcode;
    uint8_t success: 1;
    uint8_t master_sent_fail: 1;
    uint8_t padding: 6;
    uint8_t reason;
} PACKED;

struct InitButtonEventsRequest {
    uint8_t opcode;
    uint32_t event_count;
    uint32_t boot_id;
    uint32_t auto_disconnect_time: 9;
    uint32_t max_queued_packets: 5;
#ifdef _MSC_VER
    uint32_t max_queued_packets_age_low : 18;
    uint8_t max_queued_packets_age_high : 2;
#else
    uint32_t max_queued_packets_age: 20;
#endif
    uint8_t enable_hid: 1;
    uint8_t padding: 5;
} PACKED;

struct InitButtonEventsResponseWithoutBootId {
    uint8_t opcode;
    uint32_t has_queued_events: 1;
#ifdef _MSC_VER
    uint32_t timestamp_low : 31;
    uint16_t timestamp_high;
#else
    uint64_t timestamp: 47;
#endif
    uint32_t event_count;
} PACKED;

struct InitButtonEventsResponseWithBootId {
    uint8_t opcode;
    uint32_t has_queued_events: 1;
#ifdef _MSC_VER
    uint32_t timestamp_low : 31;
    uint16_t timestamp_high;
#else
    uint64_t timestamp: 47;
#endif
    uint32_t event_count;
    uint32_t boot_id;
} PACKED;

struct AckButtonEventsInd {
    uint8_t opcode;
    uint32_t event_count;
} PACKED;

struct ApiTimerInd {
    uint8_t opcode;
    uint32_t timeout; // ticks 32768 per second, 0 clears the timer
    uint32_t message;
} PACKED;

struct ApiTimerNotification {
    uint8_t opcode;
    uint32_t message;
} PACKED;

struct NameUpdatedNotification {
    uint8_t opcode;
    char name[];
} PACKED;

struct GetNameResponse {
    uint8_t opcode;
#ifdef _MSC_VER
    uint32_t timestamp_utc_ms_low;
    uint16_t timestamp_utc_ms_high;
#else
    uint64_t timestamp_utc_ms: 48;
#endif
    char name[];
} PACKED;

struct SetNameRequest {
    uint8_t opcode;
#ifdef _MSC_VER
    uint32_t timestamp_utc_ms_low;
    uint16_t timestamp_utc_ms_high : 15;
#else
    uint64_t timestamp_utc_ms: 47;
#endif
    uint16_t force_update: 1;
    char name[];
} PACKED;

struct SetNameResponse {
    uint8_t opcode;
#ifdef _MSC_VER
    uint32_t timestamp_utc_ms_low;
    uint16_t timestamp_utc_ms_high;
#else
    uint64_t timestamp_utc_ms: 48;
#endif
    char name[];
} PACKED;

struct SetConnectionParametersInd {
    uint8_t opcode;
    uint16_t intv_min, intv_max, latency, timeout;
} PACKED;

struct ButtonEventNotificationItem {
#ifdef _MSC_VER
    uint32_t timestamp_low;
    uint16_t timestamp_high;
#else
    uint64_t timestamp: 48;
#endif
    uint8_t event_encoded: 4;
    uint8_t was_queued: 1;
    uint8_t was_queued_last: 1;
    uint8_t padding: 2;
} PACKED;

struct ButtonEventNotification {
    uint8_t opcode;
    uint32_t press_counter;
    struct ButtonEventNotificationItem events[];
} PACKED;

struct GetFirmwareVersionResponse {
    uint8_t opcode;
    uint32_t version;
} PACKED;

struct StartFirmwareUpdateRequest {
    uint8_t opcode;
    uint16_t len;
    uint64_t iv;
    uint16_t status_interval;
} PACKED;

struct StartFirmwareUpdateResponse {
    uint8_t opcode;
    int start_pos;
} PACKED;

struct FirmwareUpdateDataInd {
    uint8_t opcode;
    uint8_t data[];
} PACKED;

struct FirmwareUpdateNotification {
    uint8_t opcode;
    int pos;
} PACKED;

struct SetAutoDisconnectTimeInd {
    uint8_t opcode;
    uint16_t auto_disconnect_time: 9;
    uint16_t padding: 7;
} PACKED;

struct GetBatteryLevelResponse {
    uint8_t opcode;
    uint16_t battery_level;
} PACKED;

struct SetHidStatusRequest {
    uint8_t opcode;
    uint8_t enable_hid: 1;
    uint8_t padding: 7;
} PACKED;

struct ServicesChangedConfirmationInd {
    uint8_t opcode;
    uint8_t reason;
} PACKED;

struct ForceBtDisconnectInd {
    uint8_t opcode;
    bool restart_adv;
} PACKED;

struct HidNotification {
    uint8_t opcode;
    uint16_t page;
    uint16_t usage_id;
    uint16_t duration;
} PACKED;

struct FactoryResetResponse {
    uint8_t opcode;
} PACKED;

struct GetCurrentTimeResponse {
    uint64_t opcode: 8;
    uint64_t time: 56;
} PACKED;

struct GetDeviceIdResponse {
    uint8_t opcode;
    uint8_t device_id[8];
} PACKED;

struct SetAdvParametersRequest {
    uint8_t opcode;
    bool is_active;
    bool remove_other_pairings_adv_settings;
    bool with_short_range;
    bool with_long_range;
    uint16_t adv_intervals[2]; // 0.625 ms units
    uint32_t timeout_seconds;
} PACKED;

struct SetAdvParametersResponse {
    uint8_t opcode;
} PACKED;

#ifdef _MSC_VER
#pragma pack(pop)
#endif

#endif
