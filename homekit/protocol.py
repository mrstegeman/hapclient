"""Implement the secure HTTP protocol used by HomeKit."""

from binascii import hexlify
from nacl.bindings import (crypto_aead_chacha20poly1305_ietf_encrypt,
                           crypto_aead_chacha20poly1305_ietf_decrypt,
                           crypto_scalarmult)
from nacl.exceptions import BadSignatureError
from nacl.public import PrivateKey, PublicKey
from nacl.signing import SigningKey, VerifyKey
import hashlib
import hkdf

from .secure_http import SecureHttp
from .srp import SrpClient
from .tlv import TLV


def perform_pair_setup(connection, pin, ios_pairing_id):
    """
    Perform a pair setup operation as described in chapter 4.7 page 39 ff.

    :param connection: the http connection to the target accessory
    :param pin: the setup code from the accessory
    :param ios_pairing_id: the id of the simulated ios device
    :returns: a dict with the ios device's part of the pairing information
    """
    headers = {
        'Content-Type': 'application/pairing+tlv8'
    }

    # Step #1 ios --> accessory (send SRP start request) (see page 39)
    request_tlv = TLV.encode_dict({
        TLV.kTLVType_State: TLV.M1,
        TLV.kTLVType_Method: TLV.PairSetup
    })

    connection.request('POST', '/pair-setup', request_tlv, headers)
    resp = connection.getresponse()
    response_tlv = TLV.decode_bytes(resp.read())

    # Step #3 ios --> accessory (send SRP verify request) (see page 41)
    if TLV.kTLVType_State not in response_tlv:
        return None

    if response_tlv[TLV.kTLVType_State] != TLV.M2:
        return None

    if TLV.kTLVType_Error in response_tlv:
        return None

    srp_client = SrpClient('Pair-Setup', pin)
    srp_client.set_salt(response_tlv[TLV.kTLVType_Salt])
    srp_client.set_server_public_key(response_tlv[TLV.kTLVType_PublicKey])
    client_pub_key = srp_client.get_public_key()
    client_proof = srp_client.get_proof()

    response_tlv = TLV.encode_dict({
        TLV.kTLVType_State: TLV.M3,
        TLV.kTLVType_PublicKey: SrpClient.to_byte_array(client_pub_key),
        TLV.kTLVType_Proof: SrpClient.to_byte_array(client_proof),
    })

    connection.request('POST', '/pair-setup', response_tlv, headers)
    resp = connection.getresponse()
    response_tlv = TLV.decode_bytes(resp.read())

    # Step #5 ios --> accessory (exchange request) (see page 43)

    # M4 Verification (page 43)
    if TLV.kTLVType_State not in response_tlv:
        return None

    if response_tlv[TLV.kTLVType_State] != TLV.M4:
        return None

    if TLV.kTLVType_Error in response_tlv:
        return None

    if TLV.kTLVType_Proof not in response_tlv:
        return None

    if not srp_client.verify_servers_proof(response_tlv[TLV.kTLVType_Proof]):
        return None

    # M5 Request generation (page 44)
    session_key = srp_client.get_session_key()

    ios_device_ltsk = SigningKey.generate()
    ios_device_ltpk = ios_device_ltsk.verify_key

    # reversed:
    #   Pair-Setup-Encrypt-Salt instead of Pair-Setup-Controller-Sign-Salt
    #   Pair-Setup-Encrypt-Info instead of Pair-Setup-Controller-Sign-Info
    hkdf_inst = hkdf.Hkdf('Pair-Setup-Controller-Sign-Salt'.encode(),
                          SrpClient.to_byte_array(session_key),
                          hash=hashlib.sha512)
    ios_device_x = hkdf_inst.expand('Pair-Setup-Controller-Sign-Info'.encode(),
                                    32)

    hkdf_inst = hkdf.Hkdf('Pair-Setup-Encrypt-Salt'.encode(),
                          SrpClient.to_byte_array(session_key),
                          hash=hashlib.sha512)
    session_key = hkdf_inst.expand('Pair-Setup-Encrypt-Info'.encode(), 32)

    ios_device_pairing_id = ios_pairing_id.encode()
    ios_device_info = \
        ios_device_x + ios_device_pairing_id + bytes(ios_device_ltpk)

    ios_device_signature = ios_device_ltsk.sign(ios_device_info).signature

    sub_tlv = {
        TLV.kTLVType_Identifier: ios_device_pairing_id,
        TLV.kTLVType_PublicKey: bytes(ios_device_ltpk),
        TLV.kTLVType_Signature: ios_device_signature
    }
    sub_tlv_b = TLV.encode_dict(sub_tlv)

    # taking the iOSDeviceX as key was reversed from
    # https://github.com/KhaosT/HAP-NodeJS/blob/
    #   2ea9d761d9bd7593dd1949fec621ab085af5e567/lib/HAPServer.js
    # function handlePairStepFive calling encryption.encryptAndSeal
    ciphertext = crypto_aead_chacha20poly1305_ietf_encrypt(
        bytes(sub_tlv_b),
        bytes(),
        bytes([0, 0, 0, 0]) + 'PS-Msg05'.encode(),
        session_key)
    tmp = ciphertext

    response_tlv = {
        TLV.kTLVType_State: TLV.M5,
        TLV.kTLVType_EncryptedData: tmp
    }
    body = TLV.encode_dict(response_tlv)

    connection.request('POST', '/pair-setup', body, headers)
    resp = connection.getresponse()
    response_tlv = TLV.decode_bytes(resp.read())

    # Step #7 ios (verification) (page 47)
    if response_tlv[TLV.kTLVType_State] != TLV.M6:
        return None

    if TLV.kTLVType_Error in response_tlv:
        return None

    if TLV.kTLVType_EncryptedData not in response_tlv:
        return None

    decrypted_data = crypto_aead_chacha20poly1305_ietf_decrypt(
        bytes(response_tlv[TLV.kTLVType_EncryptedData]),
        bytes(),
        bytes([0, 0, 0, 0]) + 'PS-Msg06'.encode(),
        session_key)
    if not decrypted_data:
        return None

    decrypted_data = bytearray(decrypted_data)
    response_tlv = TLV.decode_bytearray(decrypted_data)

    if TLV.kTLVType_Signature not in response_tlv:
        return None

    accessory_sig = response_tlv[TLV.kTLVType_Signature]

    if TLV.kTLVType_Identifier not in response_tlv:
        return None

    accessory_pairing_id = response_tlv[TLV.kTLVType_Identifier]

    if TLV.kTLVType_PublicKey not in response_tlv:
        return None

    accessory_ltpk = response_tlv[TLV.kTLVType_PublicKey]
    hkdf_inst = hkdf.Hkdf(
        'Pair-Setup-Accessory-Sign-Salt'.encode(),
        SrpClient.to_byte_array(srp_client.get_session_key()),
        hash=hashlib.sha512)
    accessory_x = hkdf_inst.expand('Pair-Setup-Accessory-Sign-Info'.encode(),
                                   32)

    accessory_info = accessory_x + accessory_pairing_id + accessory_ltpk

    e25519s = VerifyKey(bytes(response_tlv[TLV.kTLVType_PublicKey]))
    e25519s.verify(bytes(accessory_info), bytes(accessory_sig))

    return {
        'AccessoryPairingID': response_tlv[TLV.kTLVType_Identifier].decode(),
        'AccessoryLTPK':
            hexlify(response_tlv[TLV.kTLVType_PublicKey]).decode(),
        'iOSPairingID': ios_pairing_id,
        'iOSDeviceLTSK': hexlify(bytes(ios_device_ltsk)).decode(),
        'iOSDeviceLTPK': hexlify(bytes(ios_device_ltpk)).decode(),
    }


def get_session_keys(conn, pairing_data):
    """
    Perform a pair verify operation as described in chapter 4.8 page 47 ff.

    :param conn: the http connection to the target accessory
    :param pairing_data: the paring data as returned by perform_pair_setup
    :returns: tuple of the session keys (controller_to_accessory_key and
              accessory_to_controller_key)
    """
    headers = {
        'Content-Type': 'application/pairing+tlv8'
    }

    # Step #1 ios --> accessory (send verify start request) (page 47)
    ios_key = PrivateKey.generate()

    request_tlv = TLV.encode_dict({
        TLV.kTLVType_State: TLV.M1,
        TLV.kTLVType_PublicKey: bytes(ios_key.public_key),
    })

    conn.request('POST', '/pair-verify', request_tlv, headers)
    resp = conn.getresponse()
    response_tlv = TLV.decode_bytes(resp.read())

    # Step #3 ios --> accessory (send SRP verify request)  (page 49)
    if TLV.kTLVType_State not in response_tlv:
        return None

    if response_tlv[TLV.kTLVType_State] != TLV.M2:
        return None

    if TLV.kTLVType_PublicKey not in response_tlv:
        return None

    if TLV.kTLVType_EncryptedData not in response_tlv:
        return None

    # 1) generate shared secret
    accessorys_session_pub_key_bytes = \
        bytes(response_tlv[TLV.kTLVType_PublicKey])
    shared_secret = crypto_scalarmult(
        bytes(ios_key),
        bytes(PublicKey(accessorys_session_pub_key_bytes)))

    # 2) derive session key
    hkdf_inst = hkdf.Hkdf('Pair-Verify-Encrypt-Salt'.encode(),
                          shared_secret,
                          hash=hashlib.sha512)
    session_key = hkdf_inst.expand('Pair-Verify-Encrypt-Info'.encode(), 32)

    # 3) verify authtag on encrypted data and 4) decrypt
    encrypted = response_tlv[TLV.kTLVType_EncryptedData]
    decrypted = crypto_aead_chacha20poly1305_ietf_decrypt(
        bytes(encrypted),
        bytes(),
        bytes([0, 0, 0, 0]) + 'PV-Msg02'.encode(),
        session_key)

    if not decrypted:
        return None

    d1 = TLV.decode_bytes(decrypted)

    if TLV.kTLVType_Identifier not in d1:
        return None

    if TLV.kTLVType_Signature not in d1:
        return None

    # 5) look up pairing by accessory name
    accessory_name = d1[TLV.kTLVType_Identifier].decode()

    if pairing_data['AccessoryPairingID'] != accessory_name:
        return None

    accessory_ltpk = VerifyKey(bytes.fromhex(pairing_data['AccessoryLTPK']))

    # 6) verify accessory's signature
    accessory_sig = d1[TLV.kTLVType_Signature]
    accessory_session_pub_key_bytes = response_tlv[TLV.kTLVType_PublicKey]
    accessory_info = accessory_session_pub_key_bytes + \
        accessory_name.encode() + bytes(ios_key.public_key)
    try:
        accessory_ltpk.verify(bytes(accessory_info), bytes(accessory_sig))
    except BadSignatureError:
        return None

    # 7) create iOSDeviceInfo
    ios_device_info = bytes(ios_key.public_key) + \
        pairing_data['iOSPairingID'].encode() + \
        accessorys_session_pub_key_bytes

    # 8) sign iOSDeviceInfo with long term secret key
    ios_device_ltsk_h = pairing_data['iOSDeviceLTSK']
    ios_device_ltsk = SigningKey(bytes.fromhex(ios_device_ltsk_h))
    ios_device_signature = ios_device_ltsk.sign(ios_device_info).signature

    # 9) construct sub tlv
    sub_tlv = TLV.encode_dict({
        TLV.kTLVType_Identifier: pairing_data['iOSPairingID'].encode(),
        TLV.kTLVType_Signature: ios_device_signature
    })

    # 10) encrypt and sign
    ciphertext = crypto_aead_chacha20poly1305_ietf_encrypt(
        bytes(sub_tlv),
        bytes(),
        bytes([0, 0, 0, 0]) + 'PV-Msg03'.encode(),
        session_key)
    tmp = ciphertext

    # 11) create tlv
    request_tlv = TLV.encode_dict({
        TLV.kTLVType_State: TLV.M3,
        TLV.kTLVType_EncryptedData: tmp
    })

    # 12) send to accessory
    conn.request('POST', '/pair-verify', request_tlv, headers)
    resp = conn.getresponse()
    response_tlv = TLV.decode_bytes(resp.read())

    # Post Step #4 verification (page 51)
    if TLV.kTLVType_State not in response_tlv:
        return None

    if response_tlv[TLV.kTLVType_State] != TLV.M4:
        return None

    if TLV.kTLVType_Error in response_tlv:
        return None

    # calculate session keys
    hkdf_inst = hkdf.Hkdf('Control-Salt'.encode(),
                          shared_secret,
                          hash=hashlib.sha512)
    controller_to_accessory_key = \
        hkdf_inst.expand('Control-Write-Encryption-Key'.encode(), 32)

    hkdf_inst = hkdf.Hkdf('Control-Salt'.encode(),
                          shared_secret,
                          hash=hashlib.sha512)
    accessory_to_controller_key = \
        hkdf_inst.expand('Control-Read-Encryption-Key'.encode(), 32)

    return controller_to_accessory_key, accessory_to_controller_key


def remove_pairing(connection, pairing_data):
    """
    Remove a pairing with the device as described in Chapter 4.12 page 53.

    :param connection: the http connection to the target accessory
    :param pairing_data: the paring data as returned by perform_pair_setup
    :returns: True on success, False on error
    """
    keys = get_session_keys(connection, pairing_data)
    if not keys:
        return False

    controller_to_accessory_key, accessory_to_controller_key = keys

    sec_http = SecureHttp(connection.sock,
                          accessory_to_controller_key,
                          controller_to_accessory_key)

    request_tlv = TLV.encode_dict({
        TLV.kTLVType_State: TLV.M1,
        TLV.kTLVType_Method: TLV.RemovePairing,
        TLV.kTLVType_Identifier: pairing_data['iOSPairingID'].encode(),
    })
    response = sec_http.post('/pairings',
                             request_tlv,
                             ctype='application/pairing+tlv8')
    response_tlv = TLV.decode_bytes(response.read())
    connection.close()

    if TLV.kTLVType_State not in response_tlv:
        return False

    if response_tlv[TLV.kTLVType_State] != TLV.M2:
        return False

    if TLV.kTLVType_Error in response_tlv:
        return False

    return True
