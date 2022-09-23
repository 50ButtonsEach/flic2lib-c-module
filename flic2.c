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

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "flic2_packets.h"
#include "flic2_crypto.h"
#include "flic2.h"

#define HAS_CODED_PHY false // Can be changed to true if coded phy is supported

// Hardcoded parameters
#define LE_PUBLIC_ADDRESS 0
#define FLIC2_SIGNATURE_LENGTH 5

enum Flic2State {
    STATE_NONE,
    STATE_SEND_FULL_VERIFY1,
    STATE_SEND_FULL_VERIFY1_TEST_UNPAIRED,
    STATE_WAIT_FULL_VERIFY1,
    STATE_SEND_FULL_VERIFY2,
    STATE_WAIT_FULL_VERIFY2,
    STATE_SEND_QUICK_VERIFY,
    STATE_WAIT_QUICK_VERIFY,
    STATE_WAIT_FULL_VERIFY1_TEST_UNPAIRED,
    STATE_SEND_TEST_IF_REALLY_UNPAIRED_REQUEST,
    STATE_WAIT_TEST_IF_REALLY_UNPAIRED_RESPONSE,
    STATE_SESSION_ESTABLISHED,
    STATE_FAILED,
    STATE_RESTARTING,
    STATE_ENDED
};

static bool flic2_internal_is_paired(struct Flic2Button *button) {
    return button->d.pairing[0] != 0 || button->d.pairing[1] != 0 || button->d.pairing[2] != 0 || button->d.pairing[3] != 0;
}

static void flic2_internal_rand(struct Flic2Button *button, void *out, int len) {
    while (len > 0) {
        int part_len = len > 16 ? 16 : len;
        uint32_t buf[4];
        uint64_t w0 = button->rand_counter++ & 0xffffffffffffULL;
        w0 |= (uint64_t)(button->current_time * 1000.0) << 48;
        uint64_t data[2] = {w0, button->rand_seed_nonce};
        chaskey_16_bytes(buf, button->rand_state, (const uint32_t *)data);
        memcpy(out, buf, part_len);
        out = (uint8_t *)out + part_len;
        len -= part_len;
    }
}

static void flic2_internal_set_outgoing_packet_event(struct Flic2Button *button, struct Flic2Event *event) {
    event->type = FLIC2_EVENT_TYPE_OUTGOING_PACKET;
    event->event.outgoing_packet.data[0] = button->s.conn_id;
    
    int len = button->s.outgoing_packet_len - button->s.outgoing_packet_pos;
    if (3 + 1 + len > button->s.mtu) {
        event->event.outgoing_packet.data[0] |= 0x80;
        len = button->s.mtu - 4;
    }
    memcpy(event->event.outgoing_packet.data + 1, button->s.outgoing_packet + button->s.outgoing_packet_pos, len);
    button->s.outgoing_packet_pos += len;
    event->event.outgoing_packet.len = 1 + len;
    if (button->s.outgoing_packet_pos == button->s.outgoing_packet_len) {
        button->s.outgoing_packet_pos = 0;
        button->s.outgoing_packet_len = 0;
    }
}

static void flic2_internal_send_unsigned_packet(struct Flic2Button *button, struct Flic2Event *event, int opcode, uint32_t len) {
    button->s.outgoing_packet[0] = opcode;
    button->s.outgoing_packet_pos = 0;
    button->s.outgoing_packet_len = len;
    flic2_internal_set_outgoing_packet_event(button, event);
}

static void flic2_internal_send_signed_packet(struct Flic2Button *button, struct Flic2Event *event, int opcode, uint32_t len) {
    button->s.outgoing_packet[0] = opcode;
    button->s.outgoing_packet_pos = 0;
    button->s.outgoing_packet_len = len + FLIC2_SIGNATURE_LENGTH;
    chaskey_with_dir_and_packet_counter(button->s.outgoing_packet + len, button->s.chaskey_keys, 1, button->s.tx_counter++, button->s.outgoing_packet, len);
    flic2_internal_set_outgoing_packet_event(button, event);
}

static bool flic2_internal_verify_signature(struct Flic2Button *button, const uint8_t *packet, uint32_t len) {
    if (len < FLIC2_SIGNATURE_LENGTH) {
        return false;
    }
    struct Flic2Session *s = &button->s;
    uint8_t sig[FLIC2_SIGNATURE_LENGTH];
    chaskey_with_dir_and_packet_counter(sig, s->chaskey_keys, 0, s->rx_counter++, packet, len - FLIC2_SIGNATURE_LENGTH);
    return memcmp(sig, packet + len - FLIC2_SIGNATURE_LENGTH, FLIC2_SIGNATURE_LENGTH) == 0;
}

static void flic2_internal_schedule_firmware_update(struct Flic2Button *button, double current_utc_time, double current_time) {
    double trigger_time = button->d.next_firmware_check_timestamp_utc_ms / 1000.0 - current_utc_time + current_time;
    if (trigger_time < button->s.firmware_check_timeout) {
        trigger_time = button->s.firmware_check_timeout;
    }
    
    if (current_time >= trigger_time) {
        button->s.pending_event_check_firmware_request = true;
    } else {
        button->s.firmware_check_timeout_active = true;
        button->s.firmware_check_timeout = trigger_time;
    }
}

static void flic2_internal_after_initial_button_events_received(struct Flic2Button *button, double current_utc_time, double current_time) {
    button->s.got_initial_button_events = true;
    button->s.pending_send_conn_params = true;
    if (button->d.firmware_version >= 6 && !button->d.adv_settings_configured) {
        button->s.pending_send_adv_settings = true;
    }
    if (button->s.use_quick_verify) {
        button->s.pending_send_battery_request = true;
    } else {
        button->s.battery_timeout = current_time + 60 * 60 * 3; // 3 hours
        button->s.battery_timeout_active = true;
    }
    button->s.firmware_check_timeout = current_time + 30.0;
    if (button->s.use_quick_verify) {
        button->s.pending_send_get_firmware_version = true;
    } else {
        flic2_internal_schedule_firmware_update(button, current_utc_time, current_time);
    }
    if (button->d.name_timestamp_utc_ms != 0) {
        button->s.pending_send_set_name = true;
    } else if (!button->s.pending_send_set_name) {
        button->s.pending_send_get_name = true;
    }
}

static struct Flic2EventButtonEvent flic2_internal_build_btn_evt(enum Flic2EventButtonEventClass event_class, enum Flic2EventButtonEventType event_type, bool was_queued, double age, uint32_t event_count) {
    struct Flic2EventButtonEvent evt = { event_class, event_type, event_count, was_queued, age };
    return evt;
}

void flic2_init(struct Flic2Button *button, const uint8_t bd_addr[6], const struct Flic2DbData *init_data, const uint8_t rand_seed[16], uint64_t rand_seed_nonce) {
    memset(button, 0, sizeof(*button));
    memcpy(button->bd_addr, bd_addr, 6);
    memcpy(button->rand_state, rand_seed, 16);
    button->rand_seed_nonce = rand_seed_nonce;
    {
        uint32_t tmp[12];
        chaskey_generate_subkeys(tmp, (const uint8_t *)button->rand_state);
        memcpy(button->rand_state, tmp, 32); // We only need k and k1
    }
    
    if (init_data) {
        button->d = *init_data;
    } else {
        memset(&button->d, 0, sizeof(button->d));
    }
    button->auto_disconnect_time = 511;
    button->intv_min = 80;
    button->intv_max = 90;
    button->slave_latency = 17;
    button->supervision_timeout = 800;
    
    button->initialized = true;
}

void flic2_start(struct Flic2Button *button, double current_time, uint16_t att_mtu) {
    if (!button->initialized || att_mtu < 23) {
        return;
    }
    if (att_mtu > 130) {
        att_mtu = 130;
    }
    memset(&button->s, 0, sizeof(button->s));
    flic2_internal_rand(button, &button->s.tmp_id, sizeof(button->s.tmp_id));
    button->s.mtu = att_mtu;
    if (flic2_internal_is_paired(button)) {
        // Quick verify
        button->s.use_quick_verify = true;
        button->s.state = STATE_SEND_QUICK_VERIFY;
    } else {
        // Full verify
        button->s.state = STATE_SEND_FULL_VERIFY1;
    }
    button->current_time = current_time;
}

void flic2_set_connection_parameters(struct Flic2Button *button, int min, int max, int latency, int timeout) {
    if (!button->initialized) {
        return;
    }
    button->intv_min = min;
    button->intv_max = max;
    button->slave_latency = latency;
    button->supervision_timeout = timeout;
    if (button->s.state == STATE_SESSION_ESTABLISHED && button->s.got_initial_button_events) {
        button->s.pending_send_conn_params = true;
    }
}

void flic2_set_auto_disconnect_timeout(struct Flic2Button *button, int seconds) {
    if (!button->initialized || seconds < 0 || seconds > 511 || button->auto_disconnect_time == seconds) {
        return;
    }
    button->auto_disconnect_time = seconds;
    if (button->s.state == STATE_SESSION_ESTABLISHED && !button->s.pending_send_init) {
        button->s.pending_send_auto_disconnect_timeout = true;
    }
}
void flic2_set_name(struct Flic2Button *button, double current_utc_time, const char *name, size_t len_bytes) {
    if (!button->initialized || !flic2_internal_is_paired(button)) {
        return;
    }
    if (len_bytes > 23) {
        size_t byte_pos = 0;
        while (byte_pos < len_bytes) {
            char c = name[byte_pos];
            size_t char_byte_len = 1;
            if ((c & 0xe0) == 0xc0) {
                char_byte_len = 2;
            } else if ((c & 0xf0) == 0xe0) {
                char_byte_len = 3;
            } else if ((c & 0xf8) == 0xf0) {
                char_byte_len = 4;
            }
            if (byte_pos + char_byte_len > 23 || byte_pos + char_byte_len > len_bytes) {
                break;
            }
            byte_pos += char_byte_len;
        }
        len_bytes = byte_pos;
    }
    button->d.name.len = (uint8_t)len_bytes;
    memcpy(button->d.name.value, name, len_bytes);
    memset(button->d.name.value + len_bytes, 0, 24 - button->d.name.len);
    button->d.name_timestamp_utc_ms = (uint64_t)(current_utc_time * 1000.0);
    button->db_field_update_mask |= FLIC2_DB_FIELD_NAME | FLIC2_DB_FIELD_NAME_TIMESTAMP_UTC_MS;
    
    struct Flic2Session *s = &button->s;
    if (s->state == STATE_SESSION_ESTABLISHED) {
        s->pending_send_get_name = false;
        s->pending_send_set_name = true;
    }
}

void flic2_on_incoming_packet(struct Flic2Button *button, double current_utc_time, double current_time, const uint8_t *packet, size_t len) {
    struct Flic2Session *s = &button->s;
    if (!button->initialized || s->state == STATE_NONE) {
        return;
    }
    button->current_time = current_time;
    if (s->pending_event_button_event) {
        return;
    }
    if (len < 2) {
        return;
    }
    uint8_t packet_conn_id = packet[0] & 0x1f;
    bool newly_assigned = (packet[0] & (1 << 5)) != 0;
    bool last_fragment = (packet[0] & (1 << 7)) == 0;
    if ((packet_conn_id != 0 && packet_conn_id != s->conn_id && !newly_assigned) || (newly_assigned && s->conn_id != 0)) {
        // To another app
        return;
    }
    
    if (s->incoming_packet_pos + (len - 1) > 128) {
        // Invalid length, drop
        s->incoming_packet_pos = 0;
        return;
    }
    
    if (s->incoming_packet_pos != 0) {
        memcpy(s->incoming_packet + s->incoming_packet_pos, packet + 1, len - 1);
        s->incoming_packet_pos += (uint8_t)(len - 1);
        if (last_fragment) {
            packet = s->incoming_packet;
            len = s->incoming_packet_pos;
            s->incoming_packet_pos = 0;
        }
    } else if (!last_fragment) {
        memcpy(s->incoming_packet, packet + 1, len - 1);
        s->incoming_packet_pos = (uint8_t)(len - 1);
    } else {
        ++packet;
        --len;
    }
    
    if (!last_fragment) {
        return;
    }
    
    int opcode = packet[0];
    if (opcode == OPCODE_FROM_FLIC_NO_LOGICAL_CONNECTION_SLOTS_IND && (s->state == STATE_WAIT_FULL_VERIFY1 || s->state == STATE_WAIT_FULL_VERIFY1_TEST_UNPAIRED || s->state == STATE_WAIT_QUICK_VERIFY)) {
        const struct NoLogicalConnectionSlotsInd *p = (const struct NoLogicalConnectionSlotsInd *)packet;
        for (size_t i = 0; i < (len - 1) / sizeof(uint32_t); i++) {
            if (p->tmp_ids[i] == s->tmp_id) {
                s->state = STATE_FAILED;
                s->pending_event_failure = true;
                s->failure_code = FLIC2_FAILURE_TOO_MANY_APPS_CONNECTED;
                return;
            }
        }
        return;
    }
    
    if (opcode == OPCODE_FROM_FLIC_FULL_VERIFY_RESPONSE_1 && len >= sizeof(struct FullVerifyResponse1) && (s->state == STATE_WAIT_FULL_VERIFY1 || s->state == STATE_WAIT_FULL_VERIFY1_TEST_UNPAIRED)) {
        const struct FullVerifyResponse1 *p = (const struct FullVerifyResponse1 *)packet;
        if (p->tmp_id != s->tmp_id) {
            return;
        }
        s->conn_id = packet_conn_id;

        if (memcmp(p->address, &button->bd_addr, 6) != 0 || p->address_type != LE_PUBLIC_ADDRESS) {
            s->state = STATE_FAILED;
            s->pending_event_failure = true;
            s->failure_code = FLIC2_FAILURE_GENUINE_CHECK_FAILED;
            s->failure_subcode = FLIC2_FAILURE_GENUINE_CHECK_FAILED_SUBCODE_UNEXPECTED_BD_ADDR;
            return;
        }

        const uint8_t *msg = p->address; // 39 bytes
        uint8_t i;
        if (!ed25519_verify(p->signature, msg, 39, &i)) {
            s->state = STATE_FAILED;
            s->pending_event_failure = true;
            s->failure_code = FLIC2_FAILURE_GENUINE_CHECK_FAILED;
            s->failure_subcode = FLIC2_FAILURE_GENUINE_CHECK_FAILED_SUBCODE_INVALID_CERTIFICATE;
            return;
        }
        uint8_t full_verify_secret_key[32];
        flic2_internal_rand(button, full_verify_secret_key, 32);
        uint8_t base[32] = { 9 };
        curve25519(s->my_public_key, base, full_verify_secret_key);
        uint8_t shared_secret[32];
        curve25519(shared_secret, p->ecdh_public_key, full_verify_secret_key);
        flic2_internal_rand(button, s->client_random_bytes, 8);
        uint8_t flags = 0;
        SHA256_STATE ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, shared_secret, sizeof(shared_secret));
        sha256_update(&ctx, &i, 1);
        sha256_update(&ctx, p->random_bytes, sizeof(p->random_bytes));
        sha256_update(&ctx, s->client_random_bytes, sizeof(s->client_random_bytes));
        sha256_update(&ctx, &flags, 1);
        sha256_finish(&ctx, s->full_verify_shared_secret);

        if (s->state == STATE_WAIT_FULL_VERIFY1) {
            s->state = STATE_SEND_FULL_VERIFY2;
        } else {
            s->state = STATE_SEND_TEST_IF_REALLY_UNPAIRED_REQUEST;
        }
        return;
    }
    
    if (s->state == STATE_WAIT_QUICK_VERIFY) {
        if (opcode == OPCODE_FROM_FLIC_QUICK_VERIFY_RESPONSE && len >= sizeof(struct QuickVerifyResponse) + FLIC2_SIGNATURE_LENGTH) {
            const struct QuickVerifyResponse *rsp = (const struct QuickVerifyResponse *)packet;
            if (rsp->tmp_id != s->tmp_id) {
                // To another app
                return;
            }

            s->conn_id = packet_conn_id;

            uint32_t seed[4] = {0};
            memcpy(seed, s->client_random_bytes, 7);
            memcpy(seed + 2, rsp->random_button_bytes, 8);

            uint32_t subkeys1[12];
            uint32_t session_key[4];
            chaskey_generate_subkeys(subkeys1, button->d.pairing + 4);
            chaskey_16_bytes(session_key, subkeys1, seed);
            chaskey_generate_subkeys(s->chaskey_keys, (const uint8_t *)session_key);


            if (!flic2_internal_verify_signature(button, packet, (uint32_t)len)) {
                s->state = STATE_FAILED;
                s->pending_event_failure = true;
                s->failure_code = FLIC2_FAILURE_QUICK_VERIFY_SIGNATURE_MISMATCH;
                return;
            }

            s->state = STATE_SESSION_ESTABLISHED;
            s->verify_timeout_active = false;
            s->pending_send_init = true;
            s->pending_event_reauthenticated = true;
            return;
        }

        if (opcode == OPCODE_FROM_FLIC_QUICK_VERIFY_NEGATIVE_RESPONSE && len >= sizeof(struct QuickVerifyNegativeResponse)) {
            const struct QuickVerifyNegativeResponse *rsp = (const struct QuickVerifyNegativeResponse *)packet;

            if (rsp->tmp_id != s->tmp_id) {
                // To another app
                return;
            }

            s->state = STATE_SEND_FULL_VERIFY1_TEST_UNPAIRED;
            return;
        }
    }
    
    if (packet_conn_id == 0) {
        return;
    }
    
    if (opcode == OPCODE_FROM_FLIC_FULL_VERIFY_RESPONSE_2 && len >= sizeof(struct FullVerifyResponse2) + FLIC2_SIGNATURE_LENGTH && s->state == STATE_WAIT_FULL_VERIFY2) {
        if (!flic2_internal_verify_signature(button, packet, (uint32_t)len)) {
            s->state = STATE_FAILED;
            s->pending_event_failure = true;
            s->failure_code = FLIC2_FAILURE_GENUINE_CHECK_FAILED;
            s->failure_subcode = FLIC2_FAILURE_GENUINE_CHECK_FAILED_SUBCODE_INVALID_CALCULATED_SIGNATURE;
            return;
        }
        const struct FullVerifyResponse2 *rsp = (const struct FullVerifyResponse2 *)packet;

        if (!rsp->app_credentials_match) {
            if (rsp->cares_about_app_credentials) {
                s->state = STATE_FAILED;
                s->pending_event_failure = true;
                s->failure_code = FLIC2_FAILURE_APP_CREDENTIALS_NOT_MATCHING_DENIED_BY_BUTTON;
                return;
            } else {
                if (false) {
                    s->state = STATE_FAILED;
                    s->pending_event_failure = true;
                    s->failure_code = FLIC2_FAILURE_APP_CREDENTIALS_NOT_MATCHING_DENIED_BY_APP;
                    return;
                }
            }
        }

        uint8_t pk[32];
        uint8_t PK[2] = { 'P', 'K' };
        HMACSHA256(s->full_verify_shared_secret, 32, PK, sizeof(PK), pk);

        memcpy(button->d.uuid, rsp->button_uuid, 16);
        memcpy(&button->d.pairing, pk, 20);

        button->d.firmware_version = rsp->firmware_version;
        memcpy(button->d.serial_number, rsp->serial_number, 11);
        button->d.serial_number[11] = '\0';

        size_t name_len = rsp->name_len > 23 ? 23 : rsp->name_len;
        memcpy(button->d.name.value, rsp->name, name_len);
        memset(button->d.name.value + name_len, 0, 23 - name_len);
        button->d.name.len = name_len;
        button->d.name_timestamp_utc_ms = 0;
        button->d.battery_voltage_millivolt = (uint16_t)((rsp->battery_level * 3600U + 512U) / 1024U);
        button->d.battery_timestamp_utc_ms = (uint64_t)(current_utc_time * 1000.0);
        
        s->state = STATE_SESSION_ESTABLISHED;
        s->verify_timeout_active = false;
        s->pending_event_paired = true;
        s->pending_event_battery_voltage_updated = true;
        s->pending_send_init = true;
        return;
    }
    
    if (opcode == OPCODE_FROM_FLIC_FULL_VERIFY_FAIL_RESPONSE && len >= sizeof(struct FullVerifyFailResponse) && s->state == STATE_WAIT_FULL_VERIFY2) {
        const struct FullVerifyFailResponse *rsp = (const struct FullVerifyFailResponse *)packet;
        s->state = STATE_FAILED;
        s->pending_event_failure = true;
        if (rsp->reason == FULL_VERIFY_FAIL_REASON_INVALID_VERIFIER) {
            s->failure_code = FLIC2_FAILURE_GENUINE_CHECK_FAILED;
            s->failure_subcode = FLIC2_FAILURE_GENUINE_CHECK_FAILED_SUBCODE_INVALID_VERIFIER;
        } else if (rsp->reason == FULL_VERIFY_FAIL_REASON_NOT_IN_PUBLIC_MODE) {
            s->failure_code = FLIC2_FAILURE_BUTTON_NOT_IN_PAIRABLE_MODE;
        } else {
            s->failure_code = FLIC2_FAILURE_FULL_VERIFY_FAILED_WITH_UNKNOWN_RESULT_CODE;
            s->failure_subcode = rsp->reason;
        }
        return;
    }
    if (opcode == OPCODE_FROM_FLIC_TEST_IF_REALLY_UNPAIRED_RESPONSE && len >= sizeof(struct TestIfReallyUnpairedResponse) && s->state == STATE_WAIT_TEST_IF_REALLY_UNPAIRED_RESPONSE) {
        const struct TestIfReallyUnpairedResponse *rsp = (const struct TestIfReallyUnpairedResponse *)packet;

        uint8_t pairing_token[32], hash[32];

        uint8_t PT[22] = { 'P', 'T' };
        memcpy(PT + 2, button->d.pairing, 20);
        HMACSHA256(s->full_verify_shared_secret, 32, PT, sizeof(PT), pairing_token);

        uint8_t NE[18] = { 'N', 'E' };
        memcpy(NE + 2, pairing_token, 16);
        HMACSHA256(s->full_verify_shared_secret, 32, NE, sizeof(NE), hash);

        s->state = STATE_FAILED;

        if (memcmp(hash, rsp->result, 16) == 0) {
            // mark as unpaired
            s->conn_id = 0;
            s->pending_event_unpaired = true;
        } else {
            uint8_t EX[18] = { 'E', 'X' };
            memcpy(EX + 2, button->d.pairing, 16);
            HMACSHA256(s->full_verify_shared_secret, 32, EX, sizeof(EX), hash);
            
            if (memcmp(hash, rsp->result, 16) != 0) {
                s->pending_event_failure = true;
                s->failure_code = FLIC2_FAILURE_GENUINE_CHECK_FAILED;
                s->failure_subcode = FLIC2_FAILURE_GENUINE_CHECK_FAILED_SUBCODE_INVALID_CALCULATED_SIGNATURE;
            } else {
                // The pairing exists on the button. This code path will only be taken if someone tampered with the data over the air.
            }
        }

        return;
    }
    
    if (s->state != STATE_SESSION_ESTABLISHED) {
        // Unknown upcode for this state
        return;
    }
    
    if (len < 1 + FLIC2_SIGNATURE_LENGTH) {
        // Invalid packet
        return;
    }
    
    if (!flic2_internal_verify_signature(button, packet, (uint32_t)len)) {
        s->state = STATE_FAILED;
        s->pending_event_failure = true;
        s->failure_code = FLIC2_FAILURE_PACKET_SIGNATURE_MISMATCH;
        return;
    }

    len -= FLIC2_SIGNATURE_LENGTH;
    
    if (((opcode == OPCODE_FROM_FLIC_INIT_BUTTON_EVENTS_RESPONSE_WITH_BOOT_ID && len >= sizeof(struct InitButtonEventsResponseWithBootId)) ||
        (opcode == OPCODE_FROM_FLIC_INIT_BUTTON_EVENTS_RESPONSE_WITHOUT_BOOT_ID && len >= sizeof(struct InitButtonEventsResponseWithoutBootId))) && s->waiting_for_init_response) {
        const struct InitButtonEventsResponseWithBootId *rsp = (const struct InitButtonEventsResponseWithBootId *)packet;
        --s->num_requests_pending;
        s->waiting_for_init_response = false;
        bool boot_id_changed = (opcode == OPCODE_FROM_FLIC_INIT_BUTTON_EVENTS_RESPONSE_WITH_BOOT_ID);
        bool event_count_changed = button->d.event_count != rsp->event_count;

        if (boot_id_changed) {
            button->d.boot_id = rsp->boot_id;
            button->d.adv_settings_configured = false;
            button->db_field_update_mask |= FLIC2_DB_FIELD_BOOT_ID | FLIC2_DB_FIELD_ADV_SETTINGS_CONFIGURED;
        }
        if (event_count_changed) {
            button->d.event_count = rsp->event_count;
            button->db_field_update_mask |= FLIC2_DB_FIELD_EVENT_COUNT;
        }

#ifdef _MSC_VER
        s->init_timestamp_button_clock = (uint64_t)rsp->timestamp_low | ((uint64_t)rsp->timestamp_high << 31);
#else
        s->init_timestamp_button_clock = rsp->timestamp;
#endif
        if (!rsp->has_queued_events) {
            flic2_internal_after_initial_button_events_received(button, current_utc_time, current_time);
            s->pending_event_all_queued_button_events_processed = true;
        }
        return;
    }
    
    if (opcode == OPCODE_FROM_FLIC_BUTTON_EVENT_NOTIFICATION && len >= sizeof(struct ButtonEventNotification) + sizeof(struct ButtonEventNotificationItem)) {
        s->pending_event_button_event = true;
        if (packet != s->incoming_packet) {
            memcpy(s->incoming_packet, packet, len);
            s->incoming_packet_pos = (uint8_t)len;
            s->button_event_pos = 0;
        }
        return;
    }
    
    if (opcode == OPCODE_FROM_FLIC_SET_ADV_PARAMETERS_RESPONSE && s->waiting_for_adv_settings_response) {
        --s->num_requests_pending;
        s->waiting_for_adv_settings_response = false;
        button->d.adv_settings_configured = true;
        button->db_field_update_mask |= FLIC2_DB_FIELD_ADV_SETTINGS_CONFIGURED;
        return;
    }
    
    if ((opcode == OPCODE_FROM_FLIC_SET_NAME_RESPONSE || opcode == OPCODE_FROM_FLIC_GET_NAME_RESPONSE) && len >= sizeof(struct SetNameResponse) && s->waiting_for_name_response) {
        const struct SetNameResponse *rsp = (const struct SetNameResponse *)packet;
        --s->num_requests_pending;
        s->waiting_for_name_response = false;
        size_t new_name_len = len - sizeof(struct SetNameResponse);
        
        if (new_name_len <= 23) {
            if ((new_name_len != button->d.name.len || memcmp(rsp->name, button->d.name.value, new_name_len) != 0) && !s->pending_send_set_name) {
                // Name was updated
                button->d.name.len = (uint8_t)new_name_len;
                memcpy(button->d.name.value, rsp->name, new_name_len);
                memset(button->d.name.value + new_name_len, 0, 23 - new_name_len);
                button->d.name_timestamp_utc_ms = 0;
                button->db_field_update_mask |= FLIC2_DB_FIELD_NAME | FLIC2_DB_FIELD_NAME_TIMESTAMP_UTC_MS;
                s->pending_event_name_updated = true;
            } else if (!s->pending_send_set_name && button->d.name_timestamp_utc_ms != 0) {
                button->d.name_timestamp_utc_ms = 0;
                button->db_field_update_mask |= FLIC2_DB_FIELD_NAME_TIMESTAMP_UTC_MS;
            }
        }
        return;
    }
    
    if (opcode == OPCODE_FROM_FLIC_NAME_UPDATED_NOTIFICATION && len >= sizeof(struct NameUpdatedNotification)) {
        const struct NameUpdatedNotification *rsp = (const struct NameUpdatedNotification *)packet;
        size_t new_name_len = len - sizeof(struct SetNameResponse);
        
        if (new_name_len <= 23) {
            if ((new_name_len != button->d.name.len || memcmp(rsp->name, button->d.name.value, new_name_len) != 0) && button->d.name_timestamp_utc_ms == 0) {
                // Name was updated
                button->d.name.len = (uint8_t)new_name_len;
                memcpy(button->d.name.value, rsp->name, new_name_len);
                memset(button->d.name.value + new_name_len, 0, 23 - new_name_len);
                button->db_field_update_mask |= FLIC2_DB_FIELD_NAME;
                s->pending_event_name_updated = true;
            }
        }
        return;
    }
    
    if (opcode == OPCODE_FROM_FLIC_GET_BATTERY_LEVEL_RESPONSE && len >= sizeof(struct GetBatteryLevelResponse) && s->waiting_for_battery_response) {
        const struct GetBatteryLevelResponse *rsp = (const struct GetBatteryLevelResponse *)packet;
        --s->num_requests_pending;
        s->waiting_for_battery_response = false;
        button->d.battery_voltage_millivolt = (uint16_t)((rsp->battery_level * 3600U + 512U) / 1024U);
        button->d.battery_timestamp_utc_ms = (uint64_t)(current_utc_time * 1000.0);
        button->db_field_update_mask |= FLIC2_DB_FIELD_BATTERY_VOLTAGE_MILLIVOLT | FLIC2_DB_FIELD_BATTERY_TIMESTAMP_UTC_MS;
        s->battery_timeout = current_time + 60 * 60 * 3; // 3 hours
        s->battery_timeout_active = true;
        s->pending_event_battery_voltage_updated = true;
        return;
    }
    
    if (opcode == OPCODE_FROM_FLIC_GET_FIRMWARE_VERSION_RESPONSE && len >= sizeof(struct GetFirmwareVersionResponse) && s->waiting_for_firmware_version_response) {
        const struct GetFirmwareVersionResponse *rsp = (const struct GetFirmwareVersionResponse *)packet;
        --s->num_requests_pending;
        s->waiting_for_firmware_version_response = false;
        if (button->d.firmware_version != rsp->version) {
            s->pending_event_firmware_version_updated = true;
            button->d.firmware_version = rsp->version;
            button->db_field_update_mask |= FLIC2_DB_FIELD_FIRMWARE_VERSION;
        }
        flic2_internal_schedule_firmware_update(button, current_utc_time, current_time);
        return;
    }
    
    if (opcode == OPCODE_FROM_FLIC_START_FIRMWARE_UPDATE_RESPONSE && len >= sizeof(struct StartFirmwareUpdateResponse) && s->waiting_for_start_firmware_update_response) {
        const struct StartFirmwareUpdateResponse *rsp = (const struct StartFirmwareUpdateResponse *)packet;
        --s->num_requests_pending;
        s->waiting_for_start_firmware_update_response = false;
        int start_pos = rsp->start_pos;
        if (start_pos < 0) {
            // -1: invalid parameters
            // -2: busy
            button->d.next_firmware_check_timestamp_utc_ms = (uint64_t)((current_utc_time + 600.0) * 1000.0);
            button->db_field_update_mask |= FLIC2_DB_FIELD_NEXT_FIRMWARE_CHECK_TIMESTAMP_UTC_MS;
            flic2_internal_schedule_firmware_update(button, current_utc_time, current_time);
        } else {
            s->firmware_update_sent_pos = start_pos;
            s->firmware_update_ack_pos = start_pos;
            s->pending_send_firmware_update_data = true;
        }
        return;
    }
    
    if (opcode == OPCODE_FROM_FLIC_FIRMWARE_UPDATE_NOTIFICATION && len >= sizeof(struct FirmwareUpdateNotification) && s->pending_send_firmware_update_data) {
        const struct FirmwareUpdateNotification *p = (const struct FirmwareUpdateNotification *)packet;
        s->firmware_update_ack_pos = p->pos;
        if (s->firmware_update_ack_pos == s->firmware_update_data_len_bytes / 4 - 2) {
            // Done!
            s->pending_send_firmware_update_data = false;
            s->pending_send_force_bt_disconnect_with_restart_adv = true;
        } else if (s->firmware_update_ack_pos == 0) {
            // Invalid signature
            s->pending_send_firmware_update_data = false;
            button->d.next_firmware_check_timestamp_utc_ms = (uint64_t)((current_utc_time + 86400.0) * 1000.0);
            button->db_field_update_mask |= FLIC2_DB_FIELD_NEXT_FIRMWARE_CHECK_TIMESTAMP_UTC_MS;
            flic2_internal_schedule_firmware_update(button, current_utc_time, current_time);
        }
        return;
    }

    if (opcode == OPCODE_FROM_FLIC_PING_REQUEST) {
        s->pending_send_ping = true;
        return;
    }
}

void flic2_on_disconnected(struct Flic2Button *button) {
    if (!button->initialized) {
        return;
    }
    memset(&button->s, 0, sizeof(button->s));
}

void flic2_on_timer(struct Flic2Button *button, double current_time) {
    if (!button->initialized) {
        return;
    }
    button->current_time = current_time;
    struct Flic2Session *s = &button->s;
    if (s->restart_timeout_active && current_time >= s->restart_timeout) {
        flic2_start(button, current_time, button->s.mtu);
        return;
    }
    if (s->verify_timeout_active && current_time >= s->verify_timeout) {
        s->verify_timeout_active = false;
        if (s->state != STATE_NONE && s->state < STATE_SESSION_ESTABLISHED) {
            s->state = STATE_FAILED;
            s->pending_event_failure = true;
            s->failure_code = FLIC2_FAILURE_VERIFY_TIMED_OUT;
        }
    }
    if (s->battery_timeout_active && current_time >= s->battery_timeout) {
        s->battery_timeout_active = false;
        s->pending_send_battery_request = true;
    }
    if (s->firmware_check_timeout_active && current_time >= s->firmware_check_timeout) {
        s->firmware_check_timeout_active = false;
        s->pending_event_check_firmware_request = true;
    }
    s->timeout_is_set = false;
}

void flic2_on_downloaded_firmware(struct Flic2Button *button, double current_utc_time, double current_time, enum Flic2FirmwareDownloadResult result, const uint8_t *firmware, size_t len_bytes) {
    struct Flic2Session *s = &button->s;
    if (!button->initialized || s->state != STATE_SESSION_ESTABLISHED || !s->waiting_for_check_firmware_result) {
        return;
    }
    button->current_time = current_time;
    s->waiting_for_check_firmware_result = false;
    
    if (result == FLIC2_FIRMWARE_DOWNLOAD_RESULT_SUCCESS) {
        s->firmware_update_data = firmware;
        s->firmware_update_data_len_bytes = len_bytes;
        s->pending_send_start_firmware_update_request = true;
    } else {
        if (result == FLIC2_FIRMWARE_DOWNLOAD_RESULT_ALREADY_LATEST) {
            button->d.next_firmware_check_timestamp_utc_ms = (uint64_t)((current_utc_time + 86400.0) * 1000.0);
        } else {
            button->d.next_firmware_check_timestamp_utc_ms = (uint64_t)((current_utc_time + 120 * 60) * 1000.0);
        }
        button->db_field_update_mask |= FLIC2_DB_FIELD_NEXT_FIRMWARE_CHECK_TIMESTAMP_UTC_MS;
        flic2_internal_schedule_firmware_update(button, current_utc_time, current_time);
    }
}

bool flic2_get_next_event(struct Flic2Button *button, double current_utc_time, double current_time, struct Flic2Event *event, bool has_space_for_outgoing_packet) {
    struct Flic2Session *s = &button->s;
    event->type = FLIC2_EVENT_TYPE_NONE;
    event->db_update.type = FLIC2_DB_UPDATE_TYPE_NONE;
    if (!button->initialized || s->state == STATE_NONE) {
        return false;
    }
    button->current_time = current_time;
    if (button->db_field_update_mask != 0) {
        event->db_update.type = FLIC2_DB_UPDATE_TYPE_UPDATE;
        event->db_update.field_update_mask = button->db_field_update_mask;
        event->db_update.fields = button->d;
        button->db_field_update_mask = 0;
    } else {
        event->db_update.field_update_mask = 0;
    }
    if (s->pending_event_paired) {
        event->type = FLIC2_EVENT_TYPE_PAIRED;
        event->db_update.type = FLIC2_DB_UPDATE_TYPE_ADD;
        event->db_update.fields = button->d;
        memcpy(event->event.paired.uuid, button->d.uuid, sizeof(button->d.uuid));
        memcpy(event->event.paired.serial_number, button->d.serial_number, sizeof(button->d.serial_number));
        event->event.paired.name.len = button->d.name.len;
        memcpy(event->event.paired.name.value, button->d.name.value, sizeof(button->d.name.value));
        event->event.paired.battery_voltage_millivolt = button->d.battery_voltage_millivolt;
        event->event.paired.firmware_version = button->d.firmware_version;
        s->pending_event_paired = false;
        return true;
    }
    if (s->pending_event_reauthenticated) {
        event->type = FLIC2_EVENT_TYPE_REAUTHENTICATED;
        s->pending_event_reauthenticated = false;
        return true;
    }
    if (s->pending_event_all_queued_button_events_processed) {
        event->type = FLIC2_EVENT_TYPE_ALL_QUEUED_BUTTON_EVENTS_PROCESSED;
        s->pending_event_all_queued_button_events_processed = false;
        return true;
    }
    if (s->pending_event_button_event) {
        const struct ButtonEventNotification *p = (const struct ButtonEventNotification *)s->incoming_packet;
        int len = s->incoming_packet_pos;
        bool send_ack = false;
        bool any_was_last_queued = false;
        bool this_was_last_queued = false;
        uint32_t ec = p->press_counter;
        size_t num_items = (len - sizeof(struct ButtonEventNotification)) / sizeof(struct ButtonEventNotificationItem);
        struct Flic2EventButtonEvent evts[17 * 3];
        uint32_t evt_pos = 0;
        uint32_t ecs[17];
        ecs[num_items - 1] = ec;
        for (size_t i = num_items - 1; i-- > 0;) {
            // counter mod 4 should be 1: down, 2: hold, 3: up, 0: single click timeout
            const struct ButtonEventNotificationItem *item = &p->events[i];
            uint32_t m4 = ec % 4;
            if (m4 == 0 || m4 == 2) {
                --ec;
            }
            else {
                uint32_t type = item->event_encoded & 3;
                if ((item->event_encoded >> 3) != 0) {
                    type = 0;
                }
                if (m4 == 1) { // down
                    if (type == 2) {
                        // single click timeout
                        --ec;
                    }
                    else {
                        // should be up (type should be 0)
                        ec -= 2;
                    }
                }
                else { // up
                    if (type == 3) {
                        // hold
                        --ec;
                    }
                    else {
                        // should be down (type should be 1)
                        ec -= 2;
                    }
                }
            }
            ecs[i] = ec;
        }
        size_t j;
        for (j = 0; j < num_items && evt_pos <= s->button_event_pos; j++) {
            const struct ButtonEventNotificationItem* item = &p->events[j];
            ec = ecs[j];
            button->d.event_count = ecs[j];
            uint32_t type = item->event_encoded & 3;
            bool was_queued = item->was_queued;
            bool was_hold = false;
            bool single_click = false;
            bool double_click = false;
            bool next_up_will_be_double_click = false;
            uint32_t val = item->event_encoded;
#ifdef _MSC_VER
            uint64_t time_diff = was_queued ? (s->init_timestamp_button_clock - ((uint64_t)item->timestamp_low | ((uint64_t)item->timestamp_high << 32))) : 0;
#else
            uint64_t time_diff = was_queued ? (s->init_timestamp_button_clock - item->timestamp) : 0;
#endif
            double age = time_diff / 32768.0;
            if ((val >> 3) != 0) {
                // Button up
                type = 0;
                was_hold = (val & 4) != 0;
                single_click = (val & 2) != 0 && (val & 1) == 0;
                double_click = (val & 2) != 0 && (val & 1) != 0;
            } else if (val == 7) {
                next_up_will_be_double_click = true;
            }

            if ((type == 0 && (single_click || double_click)) || type == 2) {
                send_ack = true;
            }
            any_was_last_queued |= item->was_queued_last;
            this_was_last_queued = item->was_queued_last;

            if (type == 0) {
                evts[evt_pos++] = flic2_internal_build_btn_evt(FLIC2_EVENT_BUTTON_EVENT_CLASS_UP_OR_DOWN, FLIC2_EVENT_BUTTON_EVENT_TYPE_UP, was_queued, age, ec);
                if (!was_hold) {
                    evts[evt_pos++] = flic2_internal_build_btn_evt(FLIC2_EVENT_BUTTON_EVENT_CLASS_CLICK_OR_HOLD, FLIC2_EVENT_BUTTON_EVENT_TYPE_CLICK, was_queued, age, ec);
                    if (single_click) {
                        evts[evt_pos++] = flic2_internal_build_btn_evt(FLIC2_EVENT_BUTTON_EVENT_CLASS_SINGLE_OR_DOUBLE_CLICK_OR_HOLD, FLIC2_EVENT_BUTTON_EVENT_TYPE_SINGLE_CLICK, was_queued, age, ec);
                    }
                }
                if (single_click) {
                    evts[evt_pos++] = flic2_internal_build_btn_evt(FLIC2_EVENT_BUTTON_EVENT_CLASS_SINGLE_OR_DOUBLE_CLICK, FLIC2_EVENT_BUTTON_EVENT_TYPE_SINGLE_CLICK, was_queued, age, ec);
                }
                if (double_click) {
                    evts[evt_pos++] = flic2_internal_build_btn_evt(FLIC2_EVENT_BUTTON_EVENT_CLASS_SINGLE_OR_DOUBLE_CLICK, FLIC2_EVENT_BUTTON_EVENT_TYPE_DOUBLE_CLICK, was_queued, age, ec);

                    evts[evt_pos++] = flic2_internal_build_btn_evt(FLIC2_EVENT_BUTTON_EVENT_CLASS_SINGLE_OR_DOUBLE_CLICK_OR_HOLD, FLIC2_EVENT_BUTTON_EVENT_TYPE_DOUBLE_CLICK, was_queued, age, ec);
                }
            }
            else if (type == 1) {
                evts[evt_pos++] = flic2_internal_build_btn_evt(FLIC2_EVENT_BUTTON_EVENT_CLASS_UP_OR_DOWN, FLIC2_EVENT_BUTTON_EVENT_TYPE_DOWN, was_queued, age, ec);
            }
            else if (type == 2) {
                evts[evt_pos++] = flic2_internal_build_btn_evt(FLIC2_EVENT_BUTTON_EVENT_CLASS_SINGLE_OR_DOUBLE_CLICK, FLIC2_EVENT_BUTTON_EVENT_TYPE_SINGLE_CLICK, was_queued, age, ec);

                evts[evt_pos++] = flic2_internal_build_btn_evt(FLIC2_EVENT_BUTTON_EVENT_CLASS_SINGLE_OR_DOUBLE_CLICK_OR_HOLD, FLIC2_EVENT_BUTTON_EVENT_TYPE_SINGLE_CLICK, was_queued, age, ec);
            }
            else if (type == 3) {
                evts[evt_pos++] = flic2_internal_build_btn_evt(FLIC2_EVENT_BUTTON_EVENT_CLASS_CLICK_OR_HOLD, FLIC2_EVENT_BUTTON_EVENT_TYPE_HOLD, was_queued, age, ec);

                if (!next_up_will_be_double_click) {
                    evts[evt_pos++] = flic2_internal_build_btn_evt(FLIC2_EVENT_BUTTON_EVENT_CLASS_SINGLE_OR_DOUBLE_CLICK_OR_HOLD, FLIC2_EVENT_BUTTON_EVENT_TYPE_HOLD, was_queued, age, ec);
                }
            }
        }
        event->type = FLIC2_EVENT_TYPE_BUTTON_EVENT;
        event->event.button_event = evts[s->button_event_pos++];
        if (this_was_last_queued && s->button_event_pos == evt_pos) {
            s->pending_event_all_queued_button_events_processed = true;
        }
        if (j == num_items && s->button_event_pos == evt_pos) {
            // Save counters to db
            event->db_update.type = FLIC2_DB_UPDATE_TYPE_UPDATE;
            event->db_update.field_update_mask |= FLIC2_DB_FIELD_EVENT_COUNT;
            event->db_update.fields = button->d;
            if (send_ack) {
                s->pending_send_ack = true;
            }
            if (any_was_last_queued) {
                flic2_internal_after_initial_button_events_received(button, current_utc_time, current_time);
            }
            s->incoming_packet_pos = 0;
            s->pending_event_button_event = false;
        }
        return true;
    }
    if (s->pending_event_name_updated) {
        event->type = FLIC2_EVENT_TYPE_NAME_UPDATED;
        event->event.name_updated.length_bytes = button->d.name.len;
        memcpy(event->event.name_updated.name, button->d.name.value, button->d.name.len);
        memset(event->event.name_updated.name + button->d.name.len, 0, 24 - button->d.name.len);
        s->pending_event_name_updated = false;
        return true;
    }
    if (s->pending_event_unpaired) {
        memset(&button->d, 0, sizeof(button->d));
        memset(s, 0, sizeof(*s));
        event->type = FLIC2_EVENT_TYPE_UNPAIRED;
        event->db_update.type = FLIC2_DB_UPDATE_TYPE_DELETE;
        return true;
    }
    if (s->pending_event_failure) {
        if (flic2_internal_is_paired(button)) {
            event->type = FLIC2_EVENT_TYPE_SESSION_FAILED;
            event->event.session_failed.error_code = (enum Flic2Failure)s->failure_code;
            event->event.session_failed.subcode = s->failure_subcode;
            uint16_t att_mtu = s->mtu;
            memset(s, 0, sizeof(*s));
            s->mtu = att_mtu;
            s->state = STATE_RESTARTING;
            s->restart_timeout = current_time + 20.0;
            s->restart_timeout_active = true;
        } else {
            event->type = FLIC2_EVENT_TYPE_PAIRING_FAILED;
            event->event.pairing_failed.error_code = (enum Flic2Failure)s->failure_code;
            event->event.pairing_failed.subcode = s->failure_subcode;
        }
        s->pending_event_failure = false;
        return true;
    }
    if (s->pending_event_battery_voltage_updated) {
        event->type = FLIC2_EVENT_TYPE_BATTERY_VOLTAGE_UPDATED;
        event->event.battery_voltage_updated.millivolt = button->d.battery_voltage_millivolt;
        s->pending_event_battery_voltage_updated = false;
        return true;
    }
    if (s->pending_event_firmware_version_updated) {
        event->type = FLIC2_EVENT_TYPE_FIRMWARE_VERSION_UPDATED;
        event->event.firmware_version_updated.firmware_version = button->d.firmware_version;
        s->pending_event_firmware_version_updated = false;
        return true;
    }
    if (s->pending_event_check_firmware_request) {
        event->type = FLIC2_EVENT_TYPE_CHECK_FIRMWARE_REQUEST;
        event->event.check_firmware_request.current_version = button->d.firmware_version;
        memcpy(event->event.check_firmware_request.button_uuid, button->d.uuid, 16);
        s->waiting_for_check_firmware_result = true;
        s->pending_event_check_firmware_request = false;
        return true;
    }
    if (has_space_for_outgoing_packet) {
        if (s->outgoing_packet_pos != s->outgoing_packet_len) {
            flic2_internal_set_outgoing_packet_event(button, event);
            return true;
        } else {
            switch (s->state) {
                case STATE_SEND_FULL_VERIFY1:
                case STATE_SEND_FULL_VERIFY1_TEST_UNPAIRED: {
                    struct FullVerifyRequest1 *pkt = (struct FullVerifyRequest1 *)s->outgoing_packet;
                    pkt->tmp_id = s->tmp_id;
                    flic2_internal_send_unsigned_packet(button, event, OPCODE_TO_FLIC_FULL_VERIFY_REQUEST_1, sizeof(struct FullVerifyRequest1));
                    s->state = s->state == STATE_SEND_FULL_VERIFY1 ? STATE_WAIT_FULL_VERIFY1 : STATE_WAIT_FULL_VERIFY1_TEST_UNPAIRED;
                    s->verify_timeout = current_time + 31.0;
                    s->verify_timeout_active = true;
                    return true;
                }
                case STATE_SEND_FULL_VERIFY2: {
                    uint8_t verifier[32];
                    uint8_t AT[2] = { 'A', 'T' };
                    HMACSHA256(s->full_verify_shared_secret, 32, AT, sizeof(AT), verifier);

                    struct FullVerifyRequest2WithoutAppToken *req = (struct FullVerifyRequest2WithoutAppToken *)s->outgoing_packet;
                    memcpy(req->ecdh_public_key, s->my_public_key, 32);
                    memcpy(req->random_bytes, s->client_random_bytes, 8);
                    req->signature_variant = 0;
                    req->encryption_variant = 0;
                    req->must_validate_app_token = 0;
                    req->padding = 0;
                    memcpy(req->verifier, verifier, 16);
                    flic2_internal_send_unsigned_packet(button, event, OPCODE_TO_FLIC_FULL_VERIFY_REQUEST_2_WITHOUT_APP_TOKEN, sizeof(*req));

                    uint8_t chaskey_keys_seed[32];
                    uint8_t SK[2] = { 'S', 'K' };
                    HMACSHA256(s->full_verify_shared_secret, 32, SK, sizeof(SK), chaskey_keys_seed);
                    chaskey_generate_subkeys(s->chaskey_keys, chaskey_keys_seed);
                    
                    s->state = STATE_WAIT_FULL_VERIFY2;
                    return true;
                }
                case STATE_SEND_TEST_IF_REALLY_UNPAIRED_REQUEST: {
                    uint8_t pairing_token[32];
                    uint8_t PT[22] = { 'P', 'T' };
                    memcpy(PT + 2, button->d.pairing, 20);
                    HMACSHA256(s->full_verify_shared_secret, 32, PT, sizeof(PT), pairing_token);

                    struct TestIfReallyUnpairedRequest *req = (struct TestIfReallyUnpairedRequest *)s->outgoing_packet;
                    memcpy(req->ecdh_public_key, s->my_public_key, 32);
                    memcpy(req->random_bytes, s->client_random_bytes, 8);
                    memcpy(&req->pairing_identifier, button->d.pairing, 4);
                    memcpy(req->pairing_token, pairing_token, 16);
                    flic2_internal_send_unsigned_packet(button, event, OPCODE_TO_FLIC_TEST_IF_REALLY_UNPAIRED_REQUEST, sizeof(*req));

                    s->state = STATE_WAIT_TEST_IF_REALLY_UNPAIRED_RESPONSE;
                    return true;
                }
                case STATE_SEND_QUICK_VERIFY: {
                    struct QuickVerifyRequest *req = (struct QuickVerifyRequest *)s->outgoing_packet;
                    uint8_t randbuf[sizeof(req->random_client_bytes) + sizeof(s->tmp_id)];
                    flic2_internal_rand(button, randbuf, sizeof(randbuf));
                    memcpy(req->random_client_bytes, randbuf, sizeof(req->random_client_bytes));
                    memcpy(s->client_random_bytes, req->random_client_bytes, sizeof(req->random_client_bytes));
                    req->signature_variant = 0;
                    req->encryption_variant = 0;
                    req->padding = 0;
                    memcpy(&s->tmp_id, randbuf + sizeof(req->random_client_bytes), sizeof(s->tmp_id));
                    req->tmp_id = s->tmp_id;
                    memcpy(&req->pairing_identifier, button->d.pairing, 4);
                    flic2_internal_send_unsigned_packet(button, event, OPCODE_TO_FLIC_QUICK_VERIFY_REQUEST, sizeof(*req));
                    
                    s->state = STATE_WAIT_QUICK_VERIFY;
                    s->verify_timeout = current_time + 31.0;
                    s->verify_timeout_active = true;
                    return true;
                }
                case STATE_SESSION_ESTABLISHED: {
                    if (!s->has_sent_force_bt_disconnect_ind) {
                        if (s->pending_send_init) {
                            struct InitButtonEventsRequest *req = (struct InitButtonEventsRequest *)s->outgoing_packet;
                            req->event_count = button->d.event_count;
                            req->boot_id = button->d.boot_id;
                            req->auto_disconnect_time = button->auto_disconnect_time;
                            req->max_queued_packets = s->use_quick_verify ? 31 : 0;
#ifdef _MSC_VER
                            req->max_queued_packets_age_low = 0x3ffff;
                            req->max_queued_packets_age_high = 0x3;
#else
                            req->max_queued_packets_age = 0xfffff;
#endif
                            req->enable_hid = 0;
                            req->padding = 0;
                            flic2_internal_send_signed_packet(button, event, OPCODE_TO_FLIC_INIT_BUTTON_EVENTS_LIGHT_REQUEST, sizeof(*req));
                            ++s->num_requests_pending;
                            s->waiting_for_init_response = true;
                            s->pending_send_init = false;
                            return true;
                        }
                        if (s->pending_send_ack) {
                            struct AckButtonEventsInd *ind = (struct AckButtonEventsInd *)s->outgoing_packet;
                            ind->event_count = button->d.event_count;
                            flic2_internal_send_signed_packet(button, event, OPCODE_TO_FLIC_ACK_BUTTON_EVENTS_IND, sizeof(*ind));
                            s->pending_send_ack = false;
                            return true;
                        }
                        if (s->pending_send_conn_params) {
                            struct SetConnectionParametersInd *ind = (struct SetConnectionParametersInd *)s->outgoing_packet;
                            ind->intv_min = button->intv_min;
                            ind->intv_max = button->intv_max;
                            ind->latency = button->slave_latency;
                            ind->timeout = button->supervision_timeout;
                            flic2_internal_send_signed_packet(button, event, OPCODE_TO_FLIC_SET_CONNECTION_PARAMETERS_IND, sizeof(*ind));
                            s->pending_send_conn_params = false;
                            return true;
                        }
                        if (s->pending_send_adv_settings && s->num_requests_pending < 2) {
                            struct SetAdvParametersRequest *req = (struct SetAdvParametersRequest *)s->outgoing_packet;
                            req->is_active = true;
                            req->remove_other_pairings_adv_settings = false;
                            req->with_short_range = true;
                            req->with_long_range = HAS_CODED_PHY;
                            req->adv_intervals[0] = 160;
                            req->adv_intervals[1] = 12800;
                            req->timeout_seconds = 86400;
                            flic2_internal_send_signed_packet(button, event, OPCODE_TO_FLIC_SET_ADV_PARAMETERS_REQUEST, sizeof(*req));
                            ++s->num_requests_pending;
                            s->waiting_for_adv_settings_response = true;
                            s->pending_send_adv_settings = false;
                            return true;
                        }
                        if (s->pending_send_auto_disconnect_timeout) {
                            struct SetAutoDisconnectTimeInd *ind = (struct SetAutoDisconnectTimeInd *)s->outgoing_packet;
                            ind->auto_disconnect_time = button->auto_disconnect_time;
                            ind->padding = 0;
                            flic2_internal_send_signed_packet(button, event, OPCODE_TO_FLIC_SET_AUTO_DISCONNECT_TIME_IND, sizeof(*ind));
                            s->pending_send_auto_disconnect_timeout = false;
                            return true;
                        }
                        if (s->pending_send_ping) {
                            flic2_internal_send_signed_packet(button, event, OPCODE_TO_FLIC_PING_RESPONSE, 1);
                            s->pending_send_ping = false;
                            return true;
                        }
                        if (s->pending_send_battery_request && s->num_requests_pending < 2) {
                            flic2_internal_send_signed_packet(button, event, OPCODE_TO_FLIC_GET_BATTERY_LEVEL_REQUEST, 1);
                            ++s->num_requests_pending;
                            s->waiting_for_battery_response = true;
                            s->pending_send_battery_request = false;
                            return true;
                        }
                        if (s->pending_send_set_name && s->num_requests_pending < 2 && !s->waiting_for_name_response) {
                            struct SetNameRequest *req = (struct SetNameRequest *)s->outgoing_packet;
#ifdef _MSC_VER
                            req->timestamp_utc_ms_low = (uint32_t)button->d.name_timestamp_utc_ms;
                            req->timestamp_utc_ms_high = (uint16_t)(button->d.name_timestamp_utc_ms >> 32);
#else
                            req->timestamp_utc_ms = button->d.name_timestamp_utc_ms;
#endif
                            req->force_update = false;
                            memcpy(req->name, button->d.name.value, button->d.name.len);
                            flic2_internal_send_signed_packet(button, event, OPCODE_TO_FLIC_SET_NAME_REQUEST, sizeof(*req) + button->d.name.len);
                            ++s->num_requests_pending;
                            s->waiting_for_name_response = true;
                            s->pending_send_set_name = false;
                            return true;
                        }
                        if (s->pending_send_get_name && s->num_requests_pending < 2 && !s->waiting_for_name_response) {
                            flic2_internal_send_signed_packet(button, event, OPCODE_TO_FLIC_GET_NAME_REQUEST, 1);
                            ++s->num_requests_pending;
                            s->waiting_for_name_response = true;
                            s->pending_send_get_name = false;
                            return true;
                        }
                        if (s->pending_send_get_firmware_version && s->num_requests_pending < 2) {
                            flic2_internal_send_signed_packet(button, event, OPCODE_TO_FLIC_GET_FIRMWARE_VERSION_REQUEST, 1);
                            ++s->num_requests_pending;
                            s->waiting_for_firmware_version_response = true;
                            s->pending_send_get_firmware_version = false;
                            return true;
                        }
                        if (s->pending_send_start_firmware_update_request && s->num_requests_pending < 2) {
                            struct StartFirmwareUpdateRequest *req = (struct StartFirmwareUpdateRequest *)s->outgoing_packet;
                            req->len = (uint16_t)(s->firmware_update_data_len_bytes / 4 - 2);
                            memcpy(&req->iv, s->firmware_update_data, 8);
                            req->status_interval = 60;
                            flic2_internal_send_signed_packet(button, event, OPCODE_TO_FLIC_START_FIRMWARE_UPDATE_REQUEST, sizeof(*req));
                            ++s->num_requests_pending;
                            s->waiting_for_start_firmware_update_response = true;
                            s->pending_send_start_firmware_update_request = false;
                            return true;
                        }
                        if (s->pending_send_firmware_update_data) {
                            size_t size = s->firmware_update_data_len_bytes / 4 - 2;
                            if (s->firmware_update_sent_pos < size && s->firmware_update_sent_pos - s->firmware_update_ack_pos < 512) {
                                struct FirmwareUpdateDataInd *ind = (struct FirmwareUpdateDataInd *)s->outgoing_packet;
                                uint32_t len = (uint32_t)(size - s->firmware_update_sent_pos);
                                if (len > 30) {
                                    len = 30;
                                }
                                if (len > 512 - (s->firmware_update_sent_pos - s->firmware_update_ack_pos)) {
                                    len = 512 - (s->firmware_update_sent_pos - s->firmware_update_ack_pos);
                                }
                                memcpy(ind->data, s->firmware_update_data + 8 + s->firmware_update_sent_pos * 4, len * 4);
                                flic2_internal_send_signed_packet(button, event, OPCODE_TO_FLIC_FIRMWARE_UPDATE_DATA_IND, sizeof(*ind) + len * 4);
                                s->firmware_update_sent_pos += len;
                                return true;
                            }
                        }
                        if (s->pending_send_force_bt_disconnect_with_restart_adv) {
                            struct ForceBtDisconnectInd *ind = (struct ForceBtDisconnectInd *)s->outgoing_packet;
                            ind->restart_adv = true;
                            flic2_internal_send_signed_packet(button, event, OPCODE_TO_FLIC_FORCE_BT_DISCONNECT_IND, sizeof(*ind));
                            s->has_sent_force_bt_disconnect_ind = true;
                            s->pending_send_force_bt_disconnect_with_restart_adv = false;
                            return true;
                        }
                    }
                    break;
                }
            }
        }
    }
    if (s->restart_timeout_active && (!s->timeout_is_set || s->restart_timeout < s->current_timeout_set)) {
        s->timeout_is_set = true;
        s->current_timeout_set = s->restart_timeout;
        event->type = FLIC2_EVENT_TYPE_SET_TIMER;
        event->event.set_timer.absolute_time = s->current_timeout_set;
        return true;
    }
    if (s->verify_timeout_active && (!s->timeout_is_set || s->verify_timeout < s->current_timeout_set)) {
        s->timeout_is_set = true;
        s->current_timeout_set = s->verify_timeout;
        event->type = FLIC2_EVENT_TYPE_SET_TIMER;
        event->event.set_timer.absolute_time = s->current_timeout_set;
        return true;
    }
    if (s->battery_timeout_active && (!s->timeout_is_set || s->battery_timeout < s->current_timeout_set) && (!s->firmware_check_timeout_active || s->battery_timeout <= s->firmware_check_timeout)) {
        s->timeout_is_set = true;
        s->current_timeout_set = s->battery_timeout;
        event->type = FLIC2_EVENT_TYPE_SET_TIMER;
        event->event.set_timer.absolute_time = s->current_timeout_set;
        return true;
    }
    if (s->firmware_check_timeout_active && (!s->timeout_is_set || s->firmware_check_timeout < s->current_timeout_set)) {
        s->timeout_is_set = true;
        s->current_timeout_set = s->firmware_check_timeout;
        event->type = FLIC2_EVENT_TYPE_SET_TIMER;
        event->event.set_timer.absolute_time = s->current_timeout_set;
        return true;
    }
    if (event->db_update.field_update_mask != 0) {
        event->type = FLIC2_EVENT_TYPE_ONLY_DB_UPDATE;
        return true;
    }
    if (s->timeout_is_set && !s->restart_timeout_active && !s->verify_timeout_active && !s->battery_timeout_active && !s->firmware_check_timeout_active) {
        s->timeout_is_set = false;
        event->type = FLIC2_EVENT_TYPE_ABORT_TIMER;
        return true;
    }
    return false;
}
