import os
from .crypto import CryptoManager
from .gcp import GCPManager
from datetime import datetime
from django.conf import settings
from django import forms
import logging
from django.utils._os import safe_join

""" File manipulation functions for writing files and preparing files for download. """

# Constants for file extensions
GPG_FILE_EXTENSION = ".txt.gpg"

# Define the logger for the module
logger = logging.getLogger(__name__)

##########################################
# Helper Functions for File Manipulation #
##########################################


def create_directory_if_not_exists(directory_path: str):
    """Creates a directory if it doesn't already exist."""
    if not os.path.exists(directory_path):
        os.makedirs(directory_path)


def save_encrypted_data_to_file(file_path: str, encrypted_data: bytes):
    """Saves encrypted data to a file."""
    with open(file_path, "wb") as fp:
        fp.write(encrypted_data)


def save_encrypted_data_to_blob(
    gcpm: GCPManager,
    key_identifier: str,
    datetime_format: str,
    file_name: str,
    encrypted_data: bytes,
):
    """Saves encrypted data to a blob in GCP Storage."""
    blob_path = f"{key_identifier}-{datetime_format}/{file_name}"
    try:
        gcpm.store_in_bucket(blob_path, encrypted_data)
    except Exception as e:
        logger.error(
            f"An error occured when uploading to Cloud Storage bucket: {e}",
            exc_info=True,
        )


def import_pgp_key_from_file(cm: CryptoManager, file):
    """Imports PGP key from a file into the CryptoManager."""
    file.seek(0)
    cm.gpg.import_keys(file.read())
    imported_key = cm.gpg.list_keys()[-1]
    return imported_key["fingerprint"], imported_key["keyid"]


def data_protection_file_processing(
    cm: CryptoManager,
    mode: str,
    operation: str,
    nonce: bytes,
    aes_output: bytes,
    user_directory: str,
    file_name: str,
    aad: bytes = None,
) -> tuple:
    """Process data protection (encrypt/decrypt operations) file creation."""
    create_directory_if_not_exists(safe_join(settings.MEDIA_ROOT, user_directory))
    save_path = safe_join(settings.MEDIA_ROOT, user_directory, file_name)

    if not aad:
        aad = b""

    if operation == "decrypt":
        decoded_aes_output = try_decode_bytes_to_utf8(aes_output)
        if decoded_aes_output:
            data = cm.data_protection_text_format(
                mode,
                cm.bytes_to_hex(nonce),
                aes_output.decode("utf-8"),
                aad.decode("utf-8"),
            )
        else:
            data = cm.data_protection_text_format(
                mode,
                cm.bytes_to_hex(nonce),
                cm.bytes_to_hex(aes_output),
                aad.decode("utf-8"),
            )
    if operation == "encrypt":
        data = cm.data_protection_text_format(
            mode,
            cm.bytes_to_hex(nonce),
            cm.bytes_to_hex(aes_output),
            aad.decode("utf-8"),
        )
    return data, save_path


def try_decode_bytes_to_utf8(data: bytes) -> str | None:
    """Try to decode bytes to utf-8 string."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


##########################################
# Wireless Module File Creation Functions #
##########################################


def create_wireless_wrapped_secret_key_file(
    cm: CryptoManager,
    gcpm: GCPManager,
    wrapped_data: bytes,
    protocol: str,
    key_type: str,
    key_identifier: str,
    datetime_format: str,
) -> str:
    """Writes Encrypted key to a file for download."""
    wrapped_data_file_name = (
        f"{key_identifier}-{protocol}-{key_type}-wrapped-secret.txt"
    )
    save_path = safe_join(settings.MEDIA_ROOT, wrapped_data_file_name)

    with open(save_path, "wb") as fp:
        data = cm.wrapped_key_text_format(
            protocol, key_type, cm.bytes_to_hex(wrapped_data)
        )
        fp.write(data)

    # Check if user wants file written to GCP Storage
    if gcpm:
        save_encrypted_data_to_blob(
            gcpm,
            key_identifier,
            datetime_format,
            wrapped_data_file_name,
            data,
        )

    return wrapped_data_file_name


def create_wireless_provider_encrypted_key_files(
    form: forms.Form,
    cm: CryptoManager,
    secret_key: bytes,
    key_size: int,
    key_type: str,
    protocol: str,
    key_identifier: str,
    number_of_shares: int,
) -> list:
    """Creates XOR key shares encrypted with Provider PGP keys and saves them to files."""
    # Split the secret key into shares using XOR splitting
    shares = cm.xor_split_secret(secret_key, key_size, number_of_shares)

    # Initialize the list to store the paths to the encrypted keys (or shares) for download
    provider_files = []

    # Loop through each uploaded provider's public key file and encrypt the XOR key share with it
    for key_index, file in enumerate(
        form.cleaned_data["provider_public_keys"], start=1
    ):
        fingerprint, keyid = import_pgp_key_from_file(cm, file)
        kcv = cm.generate_kcv(shares[key_index - 1])
        xor_key_share_hex = cm.bytes_to_hex(shares[key_index - 1])
        provider_file_name = f"G+D-{key_identifier}-{protocol}-{key_type}-key-{key_index}-{keyid}{GPG_FILE_EXTENSION}"
        save_path = safe_join(settings.MEDIA_ROOT, provider_file_name)
        provider_files.append(provider_file_name)

        gd_key_share_data = cm.gd_text_format(
            xor_key_share_hex, kcv, key_type, key_size, key_index
        )
        encrypted_data = cm.gpg.encrypt(
            gd_key_share_data, fingerprint, always_trust=True, armor=False
        )
        save_encrypted_data_to_file(save_path, encrypted_data.data)

    # Return the path to the encrypted provider files for download
    return provider_files


def create_wireless_security_officers_encrypted_key_files(
    form: forms.Form,
    cm: CryptoManager,
    gcpm: GCPManager,
    key_type: str,
    key_identifier: str,
    protocol: str,
    shares: list,
    datetime_format: str,
) -> list:
    """Encrypts files containing the Shamir wrap key share with security officer (SO) PGP keys."""
    # Initialize the list to store the paths to the encrypted shares for download
    security_officer_file_names = []

    # Loop through each uploaded SO's public key files and encrypt the Shamir wrap key shares with them
    for key_index, file in enumerate(
        form.cleaned_data["security_officers_public_keys"], start=1
    ):
        fingerprint, keyid = import_pgp_key_from_file(cm, file)
        security_officer_file_name = f"SO-{key_identifier}-{protocol}-{key_type}-wrap-key-{key_index}-{keyid}{GPG_FILE_EXTENSION}"
        save_path = safe_join(settings.MEDIA_ROOT, security_officer_file_name)
        security_officer_file_names.append(security_officer_file_name)

        wrap_key_share_hex = cm.bytes_to_hex(shares[key_index - 1][1])
        so_wrap_key_share_data = cm.so_text_format(
            wrap_key_share_hex, protocol, key_type, key_index
        )
        encrypted_so_wrap_key_share_data = cm.gpg.encrypt(
            so_wrap_key_share_data, fingerprint, always_trust=True, armor=False
        )
        save_encrypted_data_to_file(save_path, encrypted_so_wrap_key_share_data.data)

        # Check if user wants file written to GCP Storage
        if gcpm:
            save_encrypted_data_to_blob(
                gcpm,
                key_identifier,
                datetime_format,
                security_officer_file_name,
                encrypted_so_wrap_key_share_data.data,
            )

    # Return the path to the SO encrypted files for download
    return security_officer_file_names


def create_wireless_fallback_yubikey_encrypted_key_files(
    form: forms.Form,
    cm: CryptoManager,
    gcpm: GCPManager,
    key_type: str,
    key_identifier: str,
    protocol: str,
    secret_key: bytes,
    datetime_format: str,
) -> list:
    """Encrypts files containing the wireless secrets with the fallback Yubikey PGP keys."""
    # Initialize the list to store the paths to the encrypted shares for download
    fallback_yubikey_file_names = []

    # Loop through each uploaded fallback Yubikey public key files and encrypt the secrets
    for key_index, file in enumerate(
        form.cleaned_data["fallback_public_keys"], start=1
    ):
        fingerprint, keyid = import_pgp_key_from_file(cm, file)
        fallback_yubikey_file_name = f"fallback-yubikey-{key_identifier}-{protocol}-{key_type}-secret-key-{key_index}-{keyid}{GPG_FILE_EXTENSION}"
        save_path = safe_join(settings.MEDIA_ROOT, fallback_yubikey_file_name)
        fallback_yubikey_file_names.append(fallback_yubikey_file_name)

        secret_key_hex = cm.bytes_to_hex(secret_key)

        encrypted_yubikey_fallback_data = cm.gpg.encrypt(
            secret_key_hex, fingerprint, always_trust=True, armor=False
        )
        save_encrypted_data_to_file(save_path, encrypted_yubikey_fallback_data.data)

        # Check if user wants file written to GCP Storage
        if gcpm:
            save_encrypted_data_to_blob(
                gcpm,
                key_identifier,
                datetime_format,
                fallback_yubikey_file_name,
                encrypted_yubikey_fallback_data.data,
            )

    # Return the path to the SO encrypted files for download
    return fallback_yubikey_file_names


def create_wireless_milenage_encrypted_file(
    form: forms.Form,
    cm: CryptoManager,
    secret_key: bytes,
    key_type: str,
    key_identifier: str,
) -> str:
    """Wraps the secret key with PGP public key of engineer handling milenage keys"""
    file = form.cleaned_data["milenage_public_key"]
    fingerprint, keyid = import_pgp_key_from_file(cm, file)

    secret_key_hex = cm.bytes_to_hex(secret_key)
    milenage_file_name = (
        f"milenage-{key_identifier}-{key_type}-key-{keyid}{GPG_FILE_EXTENSION}"
    )
    save_path = safe_join(settings.MEDIA_ROOT, milenage_file_name)

    encrypted_data = cm.gpg.encrypt(
        secret_key_hex, fingerprint, always_trust=True, armor=False
    )
    save_encrypted_data_to_file(save_path, encrypted_data.data)

    # Return the path to the encrypted milenage key files for download
    return milenage_file_name


############################################
# Key Share Module File Creation Functions #
############################################


def write_key_share_so_public_keys_to_disk(
    form: forms.Form, user_directory: str
) -> list:
    """Writes the Security Officer's public keys to a file to encrypt key or key-share."""
    path = safe_join(settings.MEDIA_ROOT, user_directory)
    create_directory_if_not_exists(path)

    # Initialize the list to store the paths to the public key files
    key_share_public_key_files = []

    # Loop through the uploaded public key files and write them to disk
    for file in form.cleaned_data["key_share_public_keys"]:
        save_path = safe_join(path, file.name)
        with open(save_path, "wb") as fp:
            for chunk in file.chunks():
                fp.write(chunk)

        key_share_public_key_files.append(save_path)

    # Return the path to the public key files for key sharing operations
    return key_share_public_key_files


def create_key_share_reconstruct_secret_file(
    cm: CryptoManager, secret_key: bytes, user_directory: str, public_key_files: list
) -> list:
    """Wraps the reconstructed secret key with PGP public key."""
    path = safe_join(settings.MEDIA_ROOT, user_directory)
    create_directory_if_not_exists(path)

    # Initialize the list to store the file names of the encrypted secret key
    key_share_files_names = []

    # Loop through the uploaded public key file and encrypt the reconstructed secret key
    for file in public_key_files:
        with open(file, "rb") as fp:
            cm.gpg.import_keys(fp.read())

        imported_key = cm.gpg.list_keys()[-1]
        fingerprint, keyid = imported_key["fingerprint"], imported_key["keyid"]
        file_name = f"key-share-reconstructed-secret-{keyid}{GPG_FILE_EXTENSION}"
        save_path = safe_join(path, file_name)
        key_share_files_names.append(file_name)

        encrypted_data = cm.gpg.encrypt(
            cm.bytes_to_hex(secret_key), fingerprint, always_trust=True, armor=False
        )
        save_encrypted_data_to_file(save_path, encrypted_data.data)

    # Return the file name of the encrypted secret key file for download
    return key_share_files_names


def create_key_share_split_secret_files(
    cm: CryptoManager, shares: list, user_directory: str, public_key_files: list
) -> list:
    """Splits the secret key into shares and encrypts each share."""
    path = safe_join(settings.MEDIA_ROOT, user_directory)
    create_directory_if_not_exists(path)

    # Initialize the list to store the file names of the encrypted shares
    key_share_files_names = []

    # Loop through the uploaded public key files and encrypt the secret key shares
    for idx, file in enumerate(public_key_files, start=1):
        with open(file, "rb") as fp:
            fp.seek(0)
            cm.gpg.import_keys(fp.read())

        imported_key = cm.gpg.list_keys()[-1]
        fingerprint, keyid = imported_key["fingerprint"], imported_key["keyid"]
        file_name = f"key-share-split-secret-index-{idx}-{keyid}{GPG_FILE_EXTENSION}"
        save_path = safe_join(path, file_name)
        key_share_files_names.append(file_name)

        share_data = (
            shares[idx - 1][1]
            if isinstance(shares[idx - 1], tuple)
            else shares[idx - 1]
        )
        encrypted_data = cm.gpg.encrypt(
            cm.bytes_to_hex(share_data), fingerprint, always_trust=True, armor=False
        )
        save_encrypted_data_to_file(save_path, encrypted_data.data)

    # Return the file namea of the encrypted secret key shares for download
    return key_share_files_names


##################################################
# Data Protection Module File Creation Functions #
##################################################


def create_data_protection_pgp_wrapped_file(
    form: forms.Form,
    cm: CryptoManager,
    task_name: str,
    mode: str,
    operation: str,
    nonce: bytes,
    aes_output: bytes,
    user_directory: str,
    aad: bytes = None,
) -> str:
    """Writes the PGP encrypted data to a file for download."""

    public_key_file = form.cleaned_data["public_key"]
    fingerprint, keyid = import_pgp_key_from_file(cm, public_key_file)
    file_name = (
        f"{task_name}-{operation}-operation-protected-{keyid}{GPG_FILE_EXTENSION}"
    )
    data, save_path = data_protection_file_processing(
        cm, mode, operation, nonce, aes_output, user_directory, file_name, aad
    )
    encrypted_data = cm.gpg.encrypt(data, fingerprint, always_trust=True, armor=False)
    save_encrypted_data_to_file(save_path, encrypted_data.data)
    return file_name


def create_data_protection_unwrapped_file(
    cm: CryptoManager,
    task_name: str,
    mode: str,
    operation: str,
    nonce: bytes,
    aes_output: bytes,
    user_directory: str,
    aad: bytes = None,
) -> str:
    """Writes data to a file for download."""
    file_name = f"{task_name}-{operation}-operation-unwrapped.txt"
    data, save_path = data_protection_file_processing(
        cm, mode, operation, nonce, aes_output, user_directory, file_name, aad
    )
    with open(save_path, "wb") as fp:
        fp.write(data)

    return file_name
