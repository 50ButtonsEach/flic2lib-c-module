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

#ifndef FLIC2_H
#define FLIC2_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/**
 * Flic 2 C module.
 * 
 * <p>This module implements the Flic 2 protocol in a platform-independent way.
 * The module uses a Flic2Button object which represents one single Flic 2 button.
 * One Flic2Button shall exist for every Flic 2 button.</p>
 * 
 * <p>BLE scanning and connection setup are not included in this module and must be handled externally.</p>
 * 
 * <p>See the Flic 2 Protocol Specification for instructions how to identify advertising buttons,
 * how to connect and which two GATT characteristics to use for communication.</p>
 * 
 * <p>The system must provide a steady clock (called steady_clock), which represents monotonic time
 * since some undefined starting point. This clock shall not be affected by discontinuous jumps in the system time
 * (e.g. if the administrator manually changes the clock). On Linux, CLOCK_MONOTONIC can be used for this purpose.
 * On embedded systems usually an RTC that starts when the system boots can be used. Ability to wait until
 * a given time point requested by this module must be implemented.</p>
 * 
 * <p>The system should also provide a system clock (wall-clock), which represents real time (UNIX timestamp).
 * On Linux CLOCK_REALTIME can be used for this purpose. Its purpose is to store timestamps for name,
 * battery measurement time and when to check for new firmware. If no system clock is available,
 * use 0 as the current time whenever requested to provide the current time.</p>
 * 
 * <p>The granularity of the time should be at least second precision, but millisecond precision or better is desired.
 * If multiple function calls are to be made in sequence, the same time can be reused for all calls.</p>
 * 
 * <p>If a Flic 2 pairing should persist across reboots or restarts of the application,
 * a database must be implemented that can add, update and delete a button.</p>
 * 
 * <p>The system must provide a cryptographically secure random number generator that can generate at least 16 bytes.</p>
 * 
 * <p>When the application starts or when a new button shall be intialized, flic2_init shall be called for every button.
 * For every newly established BLE connection and after GATT MTU Exchange (if available) has taken place, flic2_start shall be called.
 * Instead of utilizing callbacks, this module emits events that are fetched using the flic2_get_next_event function.
 * The idea is that after calling one or more functions (except for flic2_init), flic2_get_next_event shall be called in a loop until
 * no more events are returned.</p>
 */

#ifdef __cplusplus
extern "C" {
#endif
    
/**
 * Flic 2 error codes.
 * 
 * <p>Used in Flic2EventPairingFailed and Flic2EventSessionFailed to indicate the error.</p>
 * 
 * <p>The codes having SUBCODE in their name will only be used in the subcode field of the event structure.</p>
 */
enum Flic2Failure {
    /**
     * Failure indicating the verification of the button timed out, after it connected.
     */
    FLIC2_FAILURE_VERIFY_TIMED_OUT = 7,

    /**
     * Failure indicating that app credentials are not matching and the button therefore denied a pairing attempt to us.
     */
    FLIC2_FAILURE_APP_CREDENTIALS_NOT_MATCHING_DENIED_BY_BUTTON = 10,

    /**
     * Failure indicating that we denied the button's app credentials, since they don't match ours.
     */
    FLIC2_FAILURE_APP_CREDENTIALS_NOT_MATCHING_DENIED_BY_APP = 11,

    /**
     * Failure indicating the verification attempt didn't pass genuineness check.
     *
     * When this error code is used, the subcode field of the event will include one of the subcodes below.
     */
    FLIC2_FAILURE_GENUINE_CHECK_FAILED = 12,

    /**
     * Subcode indicating the button's certificate is for a different Bluetooth device address than the one we are connected to.
     */
    FLIC2_FAILURE_GENUINE_CHECK_FAILED_SUBCODE_UNEXPECTED_BD_ADDR = 0,

    /**
     * Subcode indicating the button's certificate wasn't properly signed by Shortcut Labs.
     */
    FLIC2_FAILURE_GENUINE_CHECK_FAILED_SUBCODE_INVALID_CERTIFICATE = 1,

    /**
     * Subcode indicating that the button couldn't validate our verifier.
     */
    FLIC2_FAILURE_GENUINE_CHECK_FAILED_SUBCODE_INVALID_VERIFIER = 2,

    /**
     * Subcode indicating that we couldn't verify data supposed to be signed by the button's certificate.
     */
    FLIC2_FAILURE_GENUINE_CHECK_FAILED_SUBCODE_INVALID_CALCULATED_SIGNATURE = 3,

    /**
     * Failure indicating that for an already paired button, verification of the button failed.
     */
    FLIC2_FAILURE_QUICK_VERIFY_SIGNATURE_MISMATCH = 13,

    /**
     * Failure indicating that a packet was not signed correctly.
     */
    FLIC2_FAILURE_PACKET_SIGNATURE_MISMATCH = 14,

    /**
     * Failure indicating that too many apps on this device are already communicating with the button.
     */
    FLIC2_FAILURE_TOO_MANY_APPS_CONNECTED = 15,

    /**
     * Failure indicating that the button failed the full verify process and sent an unknown result code.
     *
     * <p>The raw unknown result code is included as subcode.</p>
     */
    FLIC2_FAILURE_FULL_VERIFY_FAILED_WITH_UNKNOWN_RESULT_CODE = 18,

    /**
     * Failure that can only happen during scan when the button is not in pairable mode.
     *
     * <p>This usually happens when the button was initially held down 6 seconds and had entered pairable mode,
     * but time has passed so that when we initiated the pairing attempt, the button had already exited pairable mode.</p>
     */
    FLIC2_FAILURE_BUTTON_NOT_IN_PAIRABLE_MODE = 50,
};

/**
 * Internal Flic2Session struct.
 */
struct Flic2Session {
    uint8_t state;
    uint16_t mtu;
    
    uint32_t tmp_id;
    uint8_t conn_id;
    
    uint8_t full_verify_shared_secret[32];
    uint8_t my_public_key[32];
    uint8_t client_random_bytes[8];
    uint32_t chaskey_keys[12];
    uint64_t tx_counter;
    uint64_t rx_counter;
    
    double current_timeout_set;
    double verify_timeout;
    double battery_timeout;
    double firmware_check_timeout;
    double restart_timeout;
    
    uint64_t init_timestamp_button_clock;
    uint8_t button_event_pos;
    
    const uint8_t *firmware_update_data;
    size_t firmware_update_data_len_bytes;
    uint32_t firmware_update_sent_pos;
    uint32_t firmware_update_ack_pos;
    
    uint8_t num_requests_pending: 2;
    uint8_t waiting_for_init_response: 1;
    uint8_t waiting_for_adv_settings_response: 1;
    uint8_t waiting_for_battery_response: 1;
    uint8_t waiting_for_name_response: 1;
    uint8_t waiting_for_firmware_version_response: 1;
    uint8_t waiting_for_start_firmware_update_response: 1;
    
    uint8_t has_sent_force_bt_disconnect_ind: 1;
    
    uint8_t timeout_is_set: 1;
    uint8_t verify_timeout_active: 1;
    uint8_t battery_timeout_active: 1;
    uint8_t firmware_check_timeout_active: 1;
    uint8_t restart_timeout_active: 1;
    
    uint8_t waiting_for_check_firmware_result: 1;
    
    uint8_t pending_send_init: 1;
    uint8_t pending_send_ack: 1;
    uint8_t pending_send_conn_params: 1;
    uint8_t pending_send_adv_settings: 1;
    uint8_t pending_send_auto_disconnect_timeout: 1;
    uint8_t pending_send_ping: 1;
    uint8_t pending_send_battery_request: 1;
    uint8_t pending_send_get_name: 1;
    uint8_t pending_send_set_name: 1;
    uint8_t pending_send_get_firmware_version: 1;
    uint8_t pending_send_start_firmware_update_request: 1;
    uint8_t pending_send_firmware_update_data: 1;
    uint8_t pending_send_force_bt_disconnect_with_restart_adv: 1;
    
    uint8_t pending_event_reauthenticated: 1;
    uint8_t pending_event_all_queued_button_events_processed: 1;
    uint8_t pending_event_button_event: 1;
    uint8_t pending_event_battery_voltage_updated: 1;
    uint8_t pending_event_check_firmware_request: 1;
    uint8_t pending_event_firmware_version_updated: 1;
    uint8_t pending_event_name_updated: 1;
    
    uint8_t pending_event_failure: 1;
    uint8_t pending_event_unpaired: 1;
    uint8_t pending_event_paired: 1;
    
    uint8_t use_quick_verify: 1;
    uint8_t got_initial_button_events: 1;
    
    uint8_t failure_code;
    uint8_t failure_subcode;
    
    uint8_t incoming_packet[128];
    uint8_t incoming_packet_pos;
    
    uint8_t outgoing_packet[126];
    uint8_t outgoing_packet_pos;
    uint8_t outgoing_packet_len;
};

/**
 * Flic 2 DB data struct.
 */
struct Flic2DbData {
    /**
     * UUID of the button.
     */
    uint8_t uuid[16];
    
    /**
     * Serial number of the button (on the form AA00-A00000), followed by a null-terminator byte.
     */
    char serial_number[12];
    
    /**
     * Pairing data that will be used to re-authenticate the button on subsequent connections.
     */
    uint8_t pairing[20];
    
    /**
     * Boot id, changed every time the Flic 2 boots.
     */
    uint32_t boot_id;
    
    /**
     * Event count, used to avoid duplicate events after connection losses.
     */
    uint32_t event_count;
    
    /**
     * Advertisement settings have been sent to the button.
     */
    bool adv_settings_configured;
    
    /**
     * Firmware version.
     */
    uint32_t firmware_version;
    
    /**
     * Timestamp when the next firmware update check will be performed.
     */
    uint64_t next_firmware_check_timestamp_utc_ms;
    
    /**
     * Name of the button.
     */
    struct {
        /**
         * Length in bytes, excluding null-terminator byte.
         */
        uint8_t len;
        
        /**
         * The UTF-8 encoded name, followed by a null-terminator byte.
         */
        char value[24];
    } name;
    
    /**
     * If there is a pending name update that has not yet been confirmed by the button, contains the timestamp when the user assigned the name. Otherwise 0.
     */
    uint64_t name_timestamp_utc_ms;
    
    /**
     * Contains the latest known battery voltage, in millivolt.
     */
    uint16_t battery_voltage_millivolt;
    
    /**
     * Contains the timestamp when the battery measurement was made.
     */
    uint64_t battery_timestamp_utc_ms;
};


/**
 * Flic 2 db fields.
 * 
 * <p>Each bit corresponds to a field in Flic2DbData.</p>
 */
enum Flic2DbFields {
    FLIC2_DB_FIELD_UUID = 1 << 0,
    FLIC2_DB_FIELD_SERIAL_NUMBER = 1 < 1,
    FLIC2_DB_FIELD_PAIRING = 1 << 2,
    FLIC2_DB_FIELD_BOOT_ID = 1 << 3,
    FLIC2_DB_FIELD_EVENT_COUNT = 1 << 4,
    FLIC2_DB_FIELD_ADV_SETTINGS_CONFIGURED = 1 << 5,
    FLIC2_DB_FIELD_FIRMWARE_VERSION = 1 << 6,
    FLIC2_DB_FIELD_NEXT_FIRMWARE_CHECK_TIMESTAMP_UTC_MS = 1 << 7,
    FLIC2_DB_FIELD_NAME = 1 << 8,
    FLIC2_DB_FIELD_NAME_TIMESTAMP_UTC_MS = 1 << 9,
    FLIC2_DB_FIELD_BATTERY_VOLTAGE_MILLIVOLT = 1 << 10,
    FLIC2_DB_FIELD_BATTERY_TIMESTAMP_UTC_MS = 1 << 11
};

/**
 * Flic 2 button struct.
 * 
 * <p>Represents a Flic button and contains all state needed needed for a connection (and reconnections).</p>
 * 
 * <p>The content should be treated as opaque to the API user.</p>
 * 
 */
struct Flic2Button {
    uint8_t initialized: 1;
    
    uint32_t rand_state[8];
    uint64_t rand_seed_nonce;
    uint64_t rand_counter;
    uint8_t bd_addr[6];
    
    double current_time;
    
    uint16_t auto_disconnect_time;
    uint16_t intv_min, intv_max, slave_latency, supervision_timeout;
    
    uint32_t db_field_update_mask;
    
    struct Flic2DbData d;
    struct Flic2Session s;
};

/**
 * Flic 2 firmware download result.
 * 
 * <p>After a FLIC2_EVENT_TYPE_CHECK_FIRMWARE_REQUEST event is emitted, the user is supposed to perform
 * an internet request to check for a firmware update. The user supplies the result to flic2_on_downloaded_firmware.</p>
 */
enum Flic2FirmwareDownloadResult {
    /**
     * The firmware check was ok and a new firmware was available and has been downloaded.
     */
    FLIC2_FIRMWARE_DOWNLOAD_RESULT_SUCCESS,
    
    /**
     * The firmware check was ok but no new version is available.
     */
    FLIC2_FIRMWARE_DOWNLOAD_RESULT_ALREADY_LATEST,
    
    /**
     * The firmware check failed for any reason.
     */
    FLIC2_FIRMWARE_DOWNLOAD_RESULT_FAILED,
};

/**
 * Flic 2 event type.
 * 
 * <p>Type of event emitted by flic2_get_next_event.</p>
 * 
 * <p>Event specific data fields are present in the event field of the Flic2Event struct.</p>
 */
enum Flic2EventType {
    /**
     * No event was emitted.
     */
    FLIC2_EVENT_TYPE_NONE,
    
    /**
     * Event indicating that only a db update shall be performed.
     */
    FLIC2_EVENT_TYPE_ONLY_DB_UPDATE,
    
    /**
     * Event indicating that the user shall set a timer.
     * 
     * <p>If a timer is already active, it shall be aborted and replaced with this one.</p>
     */
    FLIC2_EVENT_TYPE_SET_TIMER,
    
    /**
     * Event indicating that the previously set timer shall be aborted.
     */
    FLIC2_EVENT_TYPE_ABORT_TIMER,
    
    /**
     * Event indicating that an outgoing packet should be written to the button using a GATT Write Without Response command.
     */
    FLIC2_EVENT_TYPE_OUTGOING_PACKET,
    
    /**
     * Event indicating that Flic 2 pairing finished successfully.
     */
    FLIC2_EVENT_TYPE_PAIRED,
    
    /**
     * Event indicating that the pairing has been removed from the Flic 2 button, usually due to a factory reset.
     * 
     * <p>This event will include a FLIC2_DB_UPDATE_TYPE_DELETE database update.</p>
     * 
     * <p>When this event occurs, the BLE connection should be terminated and this button
     * should be removed from any user interface listing buttons, or an indication that the
     * button has been unpaired. The user will need to pair it again in order to use it again.</p>
     * 
     * <p>When this event is emitted, the session is also automatically terminated and a possible
     * outstanding timer shall be aborted. The state of the button object is as if flic2_init was
     * called again with the init_data field set to NULL.</p>
     */
    FLIC2_EVENT_TYPE_UNPAIRED,
    
    /**
     * Event indicating that Flic 2 pairing failed.
     * 
     * <p>This will only be emitted if the Flic 2 is not paired.</p>
     * 
     * <p>At this point the BLE connection should be terminated and the failure reason reported to the user.</p>
     */
    FLIC2_EVENT_TYPE_PAIRING_FAILED,
    
    /**
     * Event indicating that the Flic 2 session broke or establishment failed.
     * 
     * <p>This will only be emitted if the Flic 2 is already paired.</p>
     * 
     * <p>Generally it's recommended to disconnect the Flic 2 at this point and reconnect some time later.
     * Otherwise a timer will be started and re-establishment will automatically be attempted after a while.</p>
     */
    FLIC2_EVENT_TYPE_SESSION_FAILED,
    
    /**
     * Event indicating that a session has successfully been established to the Flic 2 that was already paired.
     */
    FLIC2_EVENT_TYPE_REAUTHENTICATED,
    
    /**
     * Event containing a button event that was either queued or did just occur.
     */
    FLIC2_EVENT_TYPE_BUTTON_EVENT,
    
    /**
     * Event indicating that all queued button events have now been processed and emitted.
     */
    FLIC2_EVENT_TYPE_ALL_QUEUED_BUTTON_EVENTS_PROCESSED,
    
    /**
     * Event indicating that the name was updated.
     * 
     * <p>Emitted when someone else has updated the name.</p>
     */
    FLIC2_EVENT_TYPE_NAME_UPDATED,
    
    /**
     * Event indicating that new information about the battery voltage has been received.
     */
    FLIC2_EVENT_TYPE_BATTERY_VOLTAGE_UPDATED,
    
    /**
     * Event indicating that the user should at this point send an internet request to check for a firmware update.
     * 
     * <p>See the Flic 2 Protocol Specification for how to make the internet request.
     * The result should be delivered by calling flic2_on_downloaded_firmware.</p>
     * 
     * <p>If the device does not have internet support, this event can be ignored.</p>
     */
    FLIC2_EVENT_TYPE_CHECK_FIRMWARE_REQUEST,
    
    /**
     * Event indicating that the button has indicated it has a new firmware version compared to the latest known version.
     */
    FLIC2_EVENT_TYPE_FIRMWARE_VERSION_UPDATED
};

/**
 * Flic 2 db update type.
 * 
 * <p>For every event emitted, a database update can also be requested to be performed by the user.</p>
 */
enum Flic2DbUpdateType {
    /**
     * No database update requested for this event.
     */
    FLIC2_DB_UPDATE_TYPE_NONE,
    
    /**
     * A database request to add a new Flic 2 button. This will only be emitted for FLIC2_EVENT_TYPE_PAIRED.
     * 
     * <p>All Flic2DbData fields shall be written to persistent storage.</p>
     */
    FLIC2_DB_UPDATE_TYPE_ADD,
    
    /**
     * A database request to update Flic 2 button data.
     * 
     * <p>The field_update_mask in the Flic2DbUpdate struct will indicate which fields have been changed.</p>
     */
    FLIC2_DB_UPDATE_TYPE_UPDATE,
    
    /**
     * A database request to delete a Flic 2 button. This will only be emitted for FLIC2_EVENT_TYPE_UNPAIRED.
     */
    FLIC2_DB_UPDATE_TYPE_DELETE
};

/**
 * Flic 2 db update struct.
 */
struct Flic2DbUpdate {
    /**
     * Update type.
     */
    enum Flic2DbUpdateType type;
    
    /**
     * In case of the FLIC2_DB_UPDATE_TYPE_UPDATE type, bitmask of which fields have been updated (see Flic2DbFields).
     */
    uint32_t field_update_mask;
    
    /**
     * In case of the FLIC2_DB_UPDATE_TYPE_ADD and FLIC2_DB_UPDATE_TYPE_UPDATE types, indicates the full current database info for this button.
     */
    struct Flic2DbData fields;
};

/**
 * Flic 2 event - set timer.
 */
struct Flic2EventSetTimer {
    /**
     * Contains an absolute time (steady clock) when the flic2_on_timer method shall be called.
     */
    double absolute_time;
};

/**
 * Flic 2 event - outgoing packet.
 */
struct Flic2EventOutgoingPacket {
    /**
     * Packet length in bytes.
     */
    uint8_t len;
    
    /**
     * Packet data bytes.
     */
    uint8_t data[127];
};

/**
 * Flic 2 event - paired.
 */
struct Flic2EventPaired {
    /**
     * UUID of the button.
     */
    uint8_t uuid[16];
    
    /**
     * Serial number of the button (on the form AA00-A00000), followed by a null-terminator byte.
     */
    char serial_number[12];
    
    /**
     * Name of the button.
     */
    struct {
        /**
         * Length in bytes, excluding null-terminator byte.
         */
        uint8_t len;
        
        /**
         * The UTF-8 encoded name, followed by a null-terminator byte.
         */
        char value[24];
    } name;
    
    /**
     * Contains the battery voltage, in millivolt.
     */
    int16_t battery_voltage_millivolt;
    
    /**
     * Firmware version.
     */
    uint32_t firmware_version;
};

/**
 * Flic 2 event - pairing failed.
 */
struct Flic2EventPairingFailed {
    /**
     * Error code.
     */
    enum Flic2Failure error_code;
    
    /**
     * Subcode (only used for some error codes).
     */
    uint8_t subcode;
};

/**
 * Flic 2 event - session failed.
 */
struct Flic2EventSessionFailed {
    /**
     * Error code.
     */
    enum Flic2Failure error_code;
    
    /**
     * Subcode (only used for some error codes).
     */
    uint8_t subcode;
};

/**
 * Button event class.
 * 
 * <p>Each time the button is interacted with, one or more events will be sent.</p>
 * 
 * <p>Usually an application only needs to listen to one event class.</p>
 * 
 * <p>Since distinguishing between single and double click needs some waiting time after the first
 * click to detect if a second press will occur or not, single click events will be delayed for the
 * last two event classes but not for the first two, it is important to pick the right event class
 * for the use case.</p>
 * 
 * <p>For a particular event class, only the specified button event types may be emitted.</p>
 */
enum Flic2EventButtonEventClass {
    /**
     * Up or down.
     * 
     * <p>Triggered on every button down or release.</p>
     */
    FLIC2_EVENT_BUTTON_EVENT_CLASS_UP_OR_DOWN,
    
    /**
     * Click or hold.
     * 
     * <p>Used if you want to distinguish between click and hold.</p>
     */
    FLIC2_EVENT_BUTTON_EVENT_CLASS_CLICK_OR_HOLD,
    
    /**
     * Single or double click.
     * 
     * <p>Used if you want to distinguish between a single click and a double click.</p>
     */
    FLIC2_EVENT_BUTTON_EVENT_CLASS_SINGLE_OR_DOUBLE_CLICK,
    
    /**
     * Single or double click or hold.
     * 
     * <p>Used if you want to distinguish between a single click, a double click and a hold.</p>
     */
    FLIC2_EVENT_BUTTON_EVENT_CLASS_SINGLE_OR_DOUBLE_CLICK_OR_HOLD
};

/**
 * Button event type.
 */
enum Flic2EventButtonEventType {
    /**
     * The button was pressed.
     */
    FLIC2_EVENT_BUTTON_EVENT_TYPE_UP,
    
    /**
     * The button was released.
     */
    FLIC2_EVENT_BUTTON_EVENT_TYPE_DOWN,
    
    /**
     * The button was clicked, and was held for at most 1 seconds between press and release.
     */
    FLIC2_EVENT_BUTTON_EVENT_TYPE_CLICK,
    
    /**
     * The button was clicked once.
     */
    FLIC2_EVENT_BUTTON_EVENT_TYPE_SINGLE_CLICK,
    
    /**
     * The button was clicked twice. The time between the first and second press must be at most 0.5 seconds.
     */
    FLIC2_EVENT_BUTTON_EVENT_TYPE_DOUBLE_CLICK,
    
    /**
     * The button was held for at least 1 second.
     */
    FLIC2_EVENT_BUTTON_EVENT_TYPE_HOLD
};

/**
 * Flic 2 event - button event.
 */
struct Flic2EventButtonEvent {
    /**
     * The button event class for this event.
     */
    enum Flic2EventButtonEventClass event_class;
    
    /**
     * The button event type for this event.
     */
    enum Flic2EventButtonEventType event_type;
    
    /**
     * An event counter that starts at zero when the Flic 2 boots and always increases.
     * 
     * <p>This value divided by four indicates roughly how many times the button has been pressed and released.</p>
     * 
     * <p>More specific, event_count mod 4 should be 1: down, 2: hold, 3: up, 0: single click timeout.</p>
     */
    uint32_t event_count;
    
    /**
     * Indicates if this button event was queued, i.e. it was pressed some time ago before connection setup completed.
     */
    bool was_queued;
    
    /**
     * If this event was queued, this value contains the age of the event, in seconds. If this event was not queued, the value will be zero.
     */
    double age;
};

/**
 * Flic 2 event - name updated.
 */
struct Flic2EventNameUpdated {
    /**
     * The length in bytes of the name (max 23).
     */
    uint8_t length_bytes;
    
    /**
     * The name (length_bytes long) followed by a null-terminator character.
     */
    char name[24];
};

/**
 * Flic 2 event - battery voltage update.
 */
struct Flic2EventBatteryVoltageUpdate {
    /**
     * The voltage measured in millivolt.
     */
    int16_t millivolt;
};

/**
 * Flic 2 event - check firmware request.
 */
struct Flic2EventCheckFirmwareRequest {
    /**
     * Current firmware version of the Flic 2 button.
     */
    uint32_t current_version;
    
    /**
     * The uuid of the Flic 2 button.
     */
    uint8_t button_uuid[16];
};

/**
 * Flic 2 event - firmware version updated.
 */
struct Flic2EventFirmwareVersionUpdated {
    /**
     * Firmware version.
     */
    uint32_t firmware_version;
};

/**
 * Flic 2 event.
 */
struct Flic2Event {
    /**
     * Contains the event type.
     */
    enum Flic2EventType type;
    
    /**
     * Contains zero or one db update request.
     */
    struct Flic2DbUpdate db_update;
    
    /**
     * Contains an event struct for the corresponding event type.
     */
    union {
        struct Flic2EventSetTimer set_timer;
        struct Flic2EventOutgoingPacket outgoing_packet;
        struct Flic2EventPaired paired;
        struct Flic2EventPairingFailed pairing_failed;
        struct Flic2EventSessionFailed session_failed;
        struct Flic2EventButtonEvent button_event;
        struct Flic2EventNameUpdated name_updated;
        struct Flic2EventBatteryVoltageUpdate battery_voltage_updated;
        struct Flic2EventCheckFirmwareRequest check_firmware_request;
        struct Flic2EventFirmwareVersionUpdated firmware_version_updated;
    } event;
};

/**
 * Initialize a Flic2Button object.
 * 
 * <p>Usually called when the application starts, loading an already paired button from the database.</p>
 * 
 * <p>Also called when a new button has been found that shall be paired.</p>
 * 
 * <p>This function must be called before any other function is called for a particular Flic2Button object.</p>
 * 
 * @param button A Flic2Button object.
 * @param bd_addr The Bluetooth Device address of the button, in little endian format (01:02:03:04:05:06 is written as 0x06, 0x05, 0x04, 0x03, 0x02, 0x01).
 * @param init_data Data retrieved from the database. Shall be NULL if the button is not paired before.
 * @param rand_seed A new random value generated by a cryptographically secure random number generator.
 * @param rand_seed_nonce If multiple buttons are initialized, the random_seed may be shared as long as this value is unique. Preferably this value comes from a counter that increments for each flic2_init call.
 */
void flic2_init(struct Flic2Button *button, const uint8_t bd_addr[6], const struct Flic2DbData *init_data, const uint8_t rand_seed[16], uint64_t rand_seed_nonce);

/**
 * Start a new Flic 2 session.
 * 
 * <p>This shall be called when a BLE connection has been established to start the Flic 2 protocol.</p>
 * 
 * <p>If a session is already running for this Flic2Button object, the current session is terminated and a potential outstanding timer or pending firmware check must be stopped.</p>
 * 
 * @param button An initialized Flic2Button object.
 * @param current_time The current time in seconds of the system's steady_clock.
 * @param att_mtu The ATT_MTU that has been negotiated. May be smaller than the actual ATT_MTU if it's unknown, but must be at least 23 (which is the default ATT_MTU). Recommended: 130.
 */
void flic2_start(struct Flic2Button *button, double current_time, uint16_t att_mtu);

/**
 * Set new connection parameters.
 * 
 * <p>Causes the Flic 2 to request new connection parameters from the master.</p>
 * 
 * <p>This function can be called any time. The values are stored in RAM and will be used for the current and future connections, but will not be persisted to the db.</p>
 * 
 * <p>The values must comply with the Bluetooth specification in order to be applied.</p>
 * 
 * @param button An initialized Flic2Button object.
 * @param min Minimum connection interval (in units of 1.25 ms).
 * @param max Maximum connection interval (in units of 1.25 ms).
 * @param latency Slave latency.
 * @param timeout Supervision timeout (in units of 100 ms).
 */
void flic2_set_connection_parameters(struct Flic2Button *button, int min, int max, int latency, int timeout);


/**
 * Set auto disconnect timeout.
 * 
 * <p>This value can be set to let the Flic 2 button automatically disconnect after some time of inactivity.</p>
 * 
 * <p>The value is stored in RAM and will be maintaned for the current and every new connection. It is not persisted in the database.</p>
 * 
 * @param button An initialized Flic2Button object.
 * @param seconds Number of seconds to disconnect after inactivity (should be at least 40, maximum 510, or 511 which indicates no timeout).
 */
void flic2_set_auto_disconnect_timeout(struct Flic2Button *button, int seconds);

/**
 * Set a new name.
 * 
 * <p>This function sets a new name for the button.</p>
 * 
 * <p>The name will be sent to the button and be stored on its flash memory.</p>
 * 
 * <p>The name must be stored as UTF-8 and maximum 23 bytes. If larger than 23 bytes, it will be capped to the last possible character boundary.</p>
 * 
 * <p>After this function is called, an event will be emitted that includes a db update with the new name.</p>
 * 
 * <p>This function can be called at any time.</p>
 * 
 * @param button An initialized Flic2Button object.
 * @param current_utc_time The current time in seconds of the system's steady_clock.
 * @param name The new name, encoded as UTF-8.
 * @param len_bytes The number of bytes of the name (not including potential null-terminator byte).
 */
void flic2_set_name(struct Flic2Button *button, double current_utc_time, const char *name, size_t len_bytes);

/**
 * Incoming packet handler.
 * 
 * <p>When a GATT notification arrives, this function shall be called with the incoming characteristic value.</p>
 * 
 * <p>Between two calls to this function for a particular button, flic2_get_next_event MUST be called until there are no more events for the same button.</p>
 * 
 * @param button An initialized Flic2Button object.
 * @param current_utc_time The current UNIX timestamp (seconds since 1970-01-01T00:00:00Z, excluding leap seconds).
 * @param current_time The current time in seconds of the system's steady_clock.
 * @param packet The characteristic value.
 * @param len The length of the characteristic value in bytes.
 */
void flic2_on_incoming_packet(struct Flic2Button *button, double current_utc_time, double current_time, const uint8_t *packet, size_t len);

/**
 * Indicate BLE disconnection.
 * 
 * <p>This function can be called to terminate the current session, which resets the internal state.</p>
 * 
 * <p>It's not required to call this function upon a BLE disconnection, but recommended.</p>
 * 
 * <p>After this function is called, a potential outstanding timer or pending firmware check must be stopped.</p>
 * 
 * @param button An initialized Flic2Button object.
 */
void flic2_on_disconnected(struct Flic2Button *button);

/**
 * Timer has triggered.
 * 
 * <p>After receiving a FLIC2_EVENT_TYPE_SET_TIMER, this function shall be called when the absolute_time in the event has been reached.</p>
 * 
 * @param button An initialized Flic2Button object.
 * @param current_time The current time in seconds of the system's steady_clock.
 */
void flic2_on_timer(struct Flic2Button *button, double current_time);

/**
 * Firmware check has been performed.
 * 
 * <p>After a FLIC2_EVENT_TYPE_CHECK_FIRMWARE_REQUEST event has been emitted and the result has been fetched over internet, this function shall be called.</p>
 * 
 * @param button An initialized Flic2Button object.
 * @param current_utc_time The current UNIX timestamp (seconds since 1970-01-01T00:00:00Z, excluding leap seconds).
 * @param current_time The current time in seconds of the system's steady clock.
 * @param result The firmware download result.
 * @param firmware If success, this is a pointer to the downloaded firmware bytes that must remain valid until the session terminates, or FLIC2_EVENT_TYPE_CHECK_FIRMWARE_REQUEST is emitted again. Should be set to NULL if not success.
 * @param len_bytes The length in bytes of the downloaded firmware (or 0 if not success).
 */
void flic2_on_downloaded_firmware(struct Flic2Button *button, double current_utc_time, double current_time, enum Flic2FirmwareDownloadResult result, const uint8_t *firmware, size_t len_bytes);

/**
 * Retrieve the next event.
 * 
 * <p>After one or more methods above are called (except flic2_init), this method should be called in a loop until it returns false to get the next event to process.</p>
 * 
 * @param button An initialized Flic2Button object.
 * @param current_utc_time The current UNIX timestamp (seconds since 1970-01-01T00:00:00Z, excluding leap seconds).
 * @param current_time The current time in seconds of the system's steady clock.
 * @param event Pointer to an event which will be written.
 * @param has_space_for_outgoing_packet Used for flow control. Set this to false if the outgoing packet buffers are full. This function can be called again later with this value set to true when there is space.
 */
bool flic2_get_next_event(struct Flic2Button *button, double current_utc_time, double current_time, struct Flic2Event *event, bool has_space_for_outgoing_packet);

#ifdef __cplusplus
}
#endif

#endif
