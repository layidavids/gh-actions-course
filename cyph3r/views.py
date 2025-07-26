from django.shortcuts import render, redirect
from cryptography.fernet import Fernet
from django.core.cache import cache
from django.views.decorators.http import require_http_methods
from cyph3r.forms import (
    WirelessKeyInfoForm,
    WirelessPGPUploadForm,
    KeyShareInfoForm,
    KeyShareReconstructForm,
    KeyShareSplitForm,
    DataProtectionForm,
    TokenGenerationForm,
)
from cyph3r.models import KeyGeneration, KeySplit, FileEncryption
from cyph3r.files import (
    create_wireless_provider_encrypted_key_files,
    create_wireless_milenage_encrypted_file,
    create_wireless_security_officers_encrypted_key_files,
    create_wireless_wrapped_secret_key_file,
    write_key_share_so_public_keys_to_disk,
    create_key_share_reconstruct_secret_file,
    create_key_share_split_secret_files,
    create_data_protection_pgp_wrapped_file,
    create_wireless_fallback_yubikey_encrypted_key_files,
)
from cryptography.exceptions import InvalidTag
from cyph3r.crypto import CryptoManager
from cyph3r.gcp import GCPManager
from cyph3r.key_tracker import total_key_shares, total_files_encrypted
from datetime import datetime
import logging
import os

"""
This module contains the views for the cyph3r app.

"""
# Define the logger for the module
logger = logging.getLogger(__name__)

# Constants for HTML templates
CYPH3R_500_ERROR_PAGE = "cyph3r/500.html"
CYPH3R_KEY_SHARE_SPLIT_PAGE = "cyph3r/key_share_templates/key-share-split.html"
CYPH3R_KEY_SHARE_RECONSTRUCT_PAGE = (
    "cyph3r/key_share_templates/key-share-reconstruct.html"
)
CYPH3R_WIRELESS_GCP_STORAGE_PAGE = "cyph3r/wireless_templates/wireless-gcp-storage.html"

##############
# Index View #
##############


@require_http_methods(["GET"])
def index(request):
    """
    Returns the Home Page
    """
    try:

        # Get the total number of keys generated
        keys_generated = KeyGeneration.objects.count()

        # Get the total number of keys shares
        key_shares = total_key_shares()

        # Get the total number of files encrypted
        files_encrypted = total_files_encrypted()

        data = {
            "keys_generated": keys_generated,
            "key_shares": key_shares,
            "files_encrypted": files_encrypted,
        }
    except Exception as e:
        logger.error(f"An error occurred in the index view: {e}", exc_info=True)
        data = {
            "keys_generated": 0,
            "key_shares": 0,
            "files_encrypted": 0,
        }

    return render(request, "cyph3r/index.html", data)


#########################
# Data Protection Views #
#########################


@require_http_methods(["GET"])
def data_protect_intro(request):
    """
    Returns the Data Protection Introduction Page
    """
    try:
        return render(request, "cyph3r/data_protect_templates/data-protect-intro.html")
    except Exception as e:
        logger.error(
            f"An error occurred in the data protect intro view: {e}", exc_info=True
        )
        return render(
            request,
            CYPH3R_500_ERROR_PAGE,
        )


@require_http_methods(["GET", "POST"])
def data_protect_info(request):
    """
    Returns the Data Protection Introduction Page
    """
    try:
        if request.method == "POST":
            form = DataProtectionForm(request.POST, request.FILES)
            if form.is_valid():
                # Ensure that the session is created. Session-key is used as folder name for file storage
                if not request.session.session_key:
                    request.session.create()

                cm = CryptoManager()
                aead_operation = form.cleaned_data.get("aead_operation")
                aead_mode = form.cleaned_data.get("aead_mode")
                aead_key = cm.hex_to_bytes(form.cleaned_data.get("aead_key"))

                if aead_operation == "encrypt":
                    plaintext = form.cleaned_data.get("plaintext").encode("utf-8")
                    nonce = cm.generate_random_key_bytes(96)
                    aad = form.cleaned_data.get("aad").encode("utf-8")
                    if aead_mode == "gcm":
                        aead_output = cm.encrypt_with_aes_gcm(
                            aead_key, nonce, plaintext, aad
                        )
                    if aead_mode == "chacha":
                        aead_output = cm.encrypt_with_chacha20_poly1305(
                            aead_key, nonce, plaintext, aad
                        )

                if aead_operation == "decrypt":
                    ciphertext = cm.hex_to_bytes(form.cleaned_data.get("ciphertext"))
                    nonce = cm.hex_to_bytes(form.cleaned_data.get("nonce"))
                    aad = form.cleaned_data.get("aad").encode("utf-8")
                    try:
                        if aead_mode == "gcm":
                            aead_output = cm.decrypt_with_aes_gcm(
                                aead_key, nonce, ciphertext, aad
                            )
                        if aead_mode == "chacha":
                            aead_output = cm.decrypt_with_chacha20_poly1305(
                                aead_key, nonce, ciphertext, aad
                            )
                    except (ValueError, InvalidTag) as e:
                        form.add_error(
                            None,
                            "Decryption failed - Ensure all parameters entered are valid",
                        )
                        return render(
                            request,
                            "cyph3r/data_protect_templates/data-protect-info.html",
                            {"form": form},
                        )
                # Update the database with the File Encryption information
                FileEncryption.objects.create(
                    key=None,
                    encryption_algorithm="AES",
                    number_of_files_encrypted=1,
                )

                pgp_encrypt = form.cleaned_data.get("pgp_encrypt")

                # Encrypt data with PGP if requested.
                if pgp_encrypt:
                    user_dir = request.session.session_key
                    task_name = form.cleaned_data.get("name")
                    data_protect_file = create_data_protection_pgp_wrapped_file(
                        form,
                        cm,
                        task_name,
                        aead_mode,
                        aead_operation,
                        nonce,
                        aead_output,
                        user_dir,
                        aad,
                    )
                    # Update the database with the File Encryption information
                    FileEncryption.objects.create(
                        key=None,
                        encryption_algorithm="PGP",
                        number_of_files_encrypted=1,
                    )
                    # Add path to secret files to session
                    request.session["data_protect_file"] = data_protect_file

                    return redirect("data-protect-download")

                else:
                    # File is not PGP encrypted
                    operation_output = {
                        "aead_output": cm.bytes_to_utf8(aead_output),
                        "nonce": cm.bytes_to_hex(nonce),
                        "aad": cm.bytes_to_utf8(aad),
                        "aead_mode": aead_mode,
                    }
                    request.session["operation_output"] = operation_output

                    return redirect("data-protect-result")
            else:
                return render(
                    request,
                    "cyph3r/data_protect_templates/data-protect-info.html",
                    {"form": form},
                )
        else:
            form = DataProtectionForm()
        return render(
            request,
            "cyph3r/data_protect_templates/data-protect-info.html",
            {"form": form},
        )
    except Exception as e:
        logger.error(
            f"An error occurred in the data protect info view: {e}", exc_info=True
        )
        return render(
            request,
            CYPH3R_500_ERROR_PAGE,
        )


@require_http_methods(["GET"])
def data_protect_download(request):
    """
    Returns Data Protection Download Page
    """
    # Get download links from session
    try:
        data_protect_file = request.session.get("data_protect_file")
        return render(
            request,
            "cyph3r/data_protect_templates/data-protect-download.html",
            {"data_protect_file": data_protect_file},
        )
    except Exception as e:
        logger.error(
            f"An error occurred in data protect download view: {e}", exc_info=True
        )
        return render(
            request,
            CYPH3R_500_ERROR_PAGE,
        )


@require_http_methods(["GET"])
def data_protect_result(request):
    """
    Returns Encrypt/Decrypt Operation Result when PGP key is not uploaded
    """
    try:
        operation_output = request.session["operation_output"]
        return render(
            request,
            "cyph3r/data_protect_templates/data-protect-result.html",
            {"operation_output": operation_output},
        )
    except Exception as e:
        logger.error(
            f"An error occurred in the data protect result view: {e}", exc_info=True
        )
        return render(
            request,
            CYPH3R_500_ERROR_PAGE,
        )


###################
# Key Share Views #
###################


@require_http_methods(["GET"])
def key_share_intro(request):
    """
    Returns Key Share Introduction Page
    """
    try:
        return render(request, "cyph3r/key_share_templates/key-share-intro.html")
    except Exception as e:
        logger.error(
            f"An error occurred in the key share intro view: {e}", exc_info=True
        )
        return render(
            request,
            CYPH3R_500_ERROR_PAGE,
        )


@require_http_methods(["GET"])
def key_share_download(request):
    """
    Returns Key Share Download Page
    """
    # Get download links from session
    try:
        secret_files = request.session.get("secret_files")
        return render(
            request,
            "cyph3r/key_share_templates/key-share-download.html",
            {"secret_files": secret_files},
        )
    except Exception as e:
        logger.error(
            f"An error occurred in key share download view: {e}", exc_info=True
        )
        return render(
            request,
            CYPH3R_500_ERROR_PAGE,
        )


@require_http_methods(["GET"])
def key_share_result(request):
    """
    Returns Key Share Result when PGP key is not uploaded
    """
    try:
        key_list = request.session["key_list"]
        return render(
            request,
            "cyph3r/key_share_templates/key-share-result.html",
            {"key_list": key_list},
        )
    except Exception as e:
        logger.error(f"An error occurred in key share result view: {e}", exc_info=True)
        return render(
            request,
            CYPH3R_500_ERROR_PAGE,
        )


@require_http_methods(["GET", "POST"])
def key_share_info(request):
    """
    Returns Key Share Info Page
    """
    try:
        # Remove any existing key share session key to ensure that session is clean and has no stale data.
        request.session.pop("submitted_officer_count", None)
        request.session.pop("key_shares", None)
        request.session.pop("scheme", None)
        request.session.pop("key_task", None)
        request.session.pop("share_count", None)
        request.session.pop("threshold_count", None)
        request.session.pop("key_list", None)

        # Check if the request is a POST request
        if request.method == "POST":

            # Populate the form with POST data and PGP public key files
            form = KeyShareInfoForm(request.POST, request.FILES)

            # Validate the form data
            if form.is_valid():

                # Ensure that the session is created.
                # Session-key is used as folder name for storing the public keys & downloadable encrypted secret
                if not request.session.session_key:
                    request.session.create()

                # Get the session key
                session_id = request.session.session_key

                # Store the form data in the session
                pgp_encrypt = form.cleaned_data.get("pgp_encrypt")
                key_task = form.cleaned_data.get("key_task")
                request.session["pgp_encrypt"] = pgp_encrypt
                request.session["key_task"] = key_task
                request.session["scheme"] = form.cleaned_data.get("scheme")
                request.session["share_count"] = form.cleaned_data.get("share_count")
                request.session["threshold_count"] = form.cleaned_data.get(
                    "threshold_count"
                )

                # write uploaded public keys to directory name session_id on the server and get list of file names if pgp_encrypt is True
                if pgp_encrypt:
                    public_key_files = write_key_share_so_public_keys_to_disk(
                        form, session_id
                    )
                    # Store the file names in the session
                    request.session["public_key_files"] = public_key_files

                # Redirect to the key share reconstruction page if the key task is 'reconstruct'
                if key_task == "reconstruct":
                    return redirect("key-share-reconstruct")

                # Redirect to the key share split page if the key task is 'split'
                if key_task == "split":
                    return redirect("key-share-split")
            else:
                return render(
                    request,
                    "cyph3r/key_share_templates/key-share-info.html",
                    {"form": form},
                )
        else:
            form = KeyShareInfoForm()
            return render(
                request,
                "cyph3r/key_share_templates/key-share-info.html",
                {"form": form},
            )
    except Exception as e:
        logger.error(
            f"An error occurred in the key share info view: {e}", exc_info=True
        )
        return render(
            request,
            CYPH3R_500_ERROR_PAGE,
        )


@require_http_methods(["GET", "POST"])
def key_share_split(request):
    """
    Returns Key Input Page for key splitting
    """
    try:
        if request.method == "POST":
            form = KeyShareSplitForm(request.POST)
            # Validate the form data
            if form.is_valid():
                # Check if the scheme is Shamir
                if request.session.get("scheme") == "shamir":
                    # Check if the key share size is 128 bits
                    if len(form.cleaned_data.get("key")) != 32:
                        form.add_error(
                            "key",
                            "key share size for shamir must be 128 bits.",
                        )
                        # Return the form with the error message
                        return render(
                            request,
                            CYPH3R_KEY_SHARE_SPLIT_PAGE,
                            {"form": form},
                        )

                # Initialize the CryptoManager
                cm = CryptoManager()

                # Get the total number of key shares required
                share_count = request.session.get("share_count")

                # Get the secret key from the form and convert to bytes
                secret_key = cm.hex_to_bytes(form.cleaned_data["key"])

                # Get the scheme from the session
                scheme = request.session.get("scheme")

                if scheme == "shamir":
                    # Retrieve the threshold number required to restore the secret
                    threshold_count = request.session.get("threshold_count")

                    # Split the secret key into shares using Shamir Secret Sharing
                    shares = cm.shamir_split_secret(
                        threshold_count, share_count, secret_key
                    )
                    # Update the database with the key split information
                    KeySplit.objects.create(
                        key=None, number_of_shares=share_count, type="SHAMIR"
                    )

                if scheme == "xor":
                    # Determine length of the secret key (bytes) e.g. 16 bytes = 128 bits
                    key_size = len(secret_key) * 8

                    # Split the secret key into shares using XOR Secret Sharing
                    shares = cm.xor_split_secret(secret_key, key_size, share_count)

                    # Update the database with the key split information
                    KeySplit.objects.create(
                        key=None, number_of_shares=share_count, type="XOR"
                    )

                # If PGP encryption is requested, encrypt the key shares with the public keys
                pgp_encrypt = request.session.get("pgp_encrypt")
                if pgp_encrypt:
                    secret_files = create_key_share_split_secret_files(
                        cm,
                        shares,
                        request.session.session_key,
                        request.session["public_key_files"],
                    )

                    # Update the database with the File Encryption information
                    FileEncryption.objects.create(
                        key=None,
                        encryption_algorithm="PGP",
                        number_of_files_encrypted=len(secret_files),
                    )

                    # Add path to secret files to session
                    request.session["secret_files"] = secret_files

                    # Return page to download the secret file
                    return redirect("key-share-download")
                else:
                    key_shares_list = []
                    for idx, share in enumerate(shares, start=1):
                        # Shamir shares are tuples with index and share
                        if isinstance(share, tuple):
                            key_shares_list.append((idx, cm.bytes_to_hex(share[1])))
                        # XOR Shares
                        else:
                            key_shares_list.append((cm.bytes_to_hex(share)))

                    # Store the key shares in the session
                    request.session["key_list"] = key_shares_list

                    # Redirect to the key share result page
                    return redirect("key-share-result")

            else:
                return render(
                    request,
                    CYPH3R_KEY_SHARE_SPLIT_PAGE,
                    {"form": form},
                )
        else:
            form = KeyShareSplitForm()
            return render(
                request,
                CYPH3R_KEY_SHARE_SPLIT_PAGE,
                {"form": form},
            )
    except Exception as e:
        logger.error(
            f"An error occurred in the key share split view: {e}", exc_info=True
        )
        return render(
            request,
            CYPH3R_500_ERROR_PAGE,
        )


@require_http_methods(["GET", "POST"])
def key_share_reconstruct(request):
    """
    Returns Key Share Input Page for key reconstruction
    """
    try:
        if request.method == "POST":
            form = KeyShareReconstructForm(request.POST)
            # Validate the form data
            if form.is_valid():
                # Check if the scheme is Shamir
                if request.session.get("scheme") == "shamir":
                    # Check if the key index is provided
                    if form.cleaned_data.get("key_index") is None:
                        form.add_error(
                            "key_index", "A key Index is required for Shamir scheme."
                        )
                        # Return the form with the error message
                        return render(
                            request,
                            CYPH3R_KEY_SHARE_RECONSTRUCT_PAGE,
                            {"form": form},
                        )
                    # Check if the key share size is 128 bits
                    if len(form.cleaned_data.get("key_share")) != 32:
                        form.add_error(
                            "key_share",
                            "key share size for shamir must be 128 bits.",
                        )
                        # Return the form with the error message
                        return render(
                            request,
                            CYPH3R_KEY_SHARE_RECONSTRUCT_PAGE,
                            {"form": form},
                        )
                # Retrieve or generate the Fernet key and store in cache
                encryption_key = cache.get(
                    f"encryption_key_{request.session.session_key}"
                )
                if not encryption_key:
                    encryption_key = Fernet.generate_key()
                    cache.set(
                        f"encryption_key_{request.session.session_key}",
                        encryption_key,
                        1800,
                    )

                # Update the database with the Key Generation information
                kg_fernet = KeyGeneration.objects.create(
                    key_id="fernet_share_encrypt_key", key_size=128, is_split=False
                )

                # Initialize the CryptoManager and Fernet object
                cm = CryptoManager()
                f = Fernet(encryption_key)

                # Initialize the list to store the encrypted key shares
                if not request.session.get("key_shares"):
                    request.session["key_shares"] = []

                if request.session.get("scheme") == "shamir":
                    # Retrieve the threshold number required to restore the secret
                    count = request.session.get("threshold_count")

                    # Retrieve the key index from the form
                    key_index = form.cleaned_data.get("key_index")

                    # Encrypt the key share using the Fernet key and store in the session
                    token = f.encrypt(cm.hex_to_bytes(form.cleaned_data["key_share"]))
                    request.session["key_shares"].append(
                        (key_index, cm.bytes_to_hex(token))
                    )  # Only JSON serializable data can be stored in session; bytes are not serializable; converting to hex

                if request.session.get("scheme") == "xor":
                    # Retrieve the share count required to restore the secret
                    count = request.session.get("share_count")

                    # Encrypt the key share using the Fernet key and store in the session
                    token = f.encrypt(cm.hex_to_bytes(form.cleaned_data["key_share"]))
                    request.session["key_shares"].append(
                        (cm.bytes_to_hex(token))
                    )  # Only JSON serializable data can be stored in session; bytes are not serializable; converting to hex

                # Update the database with the data encryption information
                FileEncryption.objects.create(
                    key=kg_fernet,
                    encryption_algorithm="AES-CBC",
                    number_of_files_encrypted=count,
                )
                # Increment the count of Security officers that have submitted their key shares
                request.session["submitted_officer_count"] += 1

                # Check if the threshold number of key shares have been submitted
                if request.session["submitted_officer_count"] > count:
                    # Initialize the list to store the key shares
                    shares = []

                    if request.session.get("scheme") == "shamir":
                        # Decrypt the encrypted key shares and store in the list
                        for idx, encrypted_share in request.session["key_shares"]:
                            share = f.decrypt(cm.hex_to_bytes(encrypted_share))
                            shares.append((idx, share))

                        # Reconstruct the key using Shamir Scheme
                        key_bytes = cm.shamir_reconstruct_secret(shares)

                    if request.session.get("scheme") == "xor":
                        # Decrypt the encrypted key shares and store in the list
                        for encrypted_share in request.session["key_shares"]:
                            share = f.decrypt(cm.hex_to_bytes(encrypted_share))
                            shares.append((share))

                        # Reconstruct the key using the xor scheme
                        key_bytes = cm.xor_reconstruct_secret(shares)

                    # Clear cache data and relevant request session keys
                    request.session.pop("submitted_officer_count", None)
                    request.session.pop("key_shares", None)
                    cache.delete(f"encryption_key_{request.session.session_key}")

                    # Check if PGP encryption is requested
                    pgp_encrypt = request.session.get("pgp_encrypt")

                    # Write the secret to a file and encrypt with PGP public keys if requested
                    if pgp_encrypt:
                        secret_files = create_key_share_reconstruct_secret_file(
                            cm,
                            key_bytes,
                            request.session.session_key,
                            request.session["public_key_files"],
                        )

                        # Update the database with the data encryption information
                        FileEncryption.objects.create(
                            key=None,
                            encryption_algorithm="PGP",
                            number_of_files_encrypted=len(secret_files),
                        )

                        # Add path to secret files to session
                        request.session["secret_files"] = secret_files

                        # Return page to download the secret file
                        return redirect("key-share-download")
                    else:
                        # Store the secret in the session
                        request.session["key_list"] = [cm.bytes_to_hex(key_bytes)]

                        # Redirect to the key share result page
                        return redirect("key-share-result")
                else:
                    return redirect("key-share-reconstruct")

            else:
                return render(
                    request,
                    CYPH3R_KEY_SHARE_RECONSTRUCT_PAGE,
                    {"form": form},
                )
        else:
            form = KeyShareReconstructForm()

            # Initialize the number of Security officers that have submitted their key shares
            if not request.session.get("submitted_officer_count"):
                request.session["submitted_officer_count"] = 1

            return render(
                request,
                CYPH3R_KEY_SHARE_RECONSTRUCT_PAGE,
                {"form": form},
            )
    except Exception as e:
        logger.error(
            f"An error occurred in the key share reconstruct view: {e}", exc_info=True
        )
        return render(
            request,
            CYPH3R_500_ERROR_PAGE,
        )


###########################
# Wireless Ceremony Views #
###########################


@require_http_methods(["GET"])
def wireless_ceremony_intro(request):
    """
    Returns partial template for the Wireless Key Ceremony Introduction
    """
    try:
        return render(request, "cyph3r/wireless_templates/wireless-ceremony-intro.html")
    except Exception as e:
        logger.error(
            f"An error occurred in the wireless ceremony intro view: {e}", exc_info=True
        )
        return render(
            request,
            CYPH3R_500_ERROR_PAGE,
        )


@require_http_methods(["GET", "POST"])
def wireless_key_info(request):
    """
    Returns Wireless Key Information form template
    """
    try:
        # Remove any existing data stored in session to ensure that session is clean and has no stale data.
        request.session.pop("security_officer_files", None)
        request.session.pop("fallback_yubikey_files", None)
        request.session.pop("provider_files", None)
        request.session.pop("wrapped_secret_key_file", None)
        if request.session.get("milenage_file"):
            request.session.pop("milenage_file", None)
        request.session.pop("key_identifier", None)
        request.session.pop("key_type", None)
        request.session.pop("protocol", None)
        request.session.pop("key_size", None)

        # Check if the request is a POST request
        if request.method == "POST":
            form = WirelessKeyInfoForm(request.POST)
            if form.is_valid():
                # Ensure that the session is created.
                if not request.session.session_key:
                    request.session.create()

                # Store key information into the session
                request.session.update(
                    {
                        "key_identifier": form.cleaned_data["key_identifier"],
                        "key_type": form.cleaned_data["key_type"],
                        "protocol": form.cleaned_data["protocol"],
                        "key_size": form.cleaned_data["key_size"],
                    }
                )
                return redirect("wireless-pgp-upload")
            else:
                return render(
                    request,
                    "cyph3r/wireless_templates/wireless-key-infos.html",
                    {"form": form},
                )
        else:
            form = WirelessKeyInfoForm()
            # Return the key info form
            return render(
                request,
                "cyph3r/wireless_templates/wireless-key-info.html",
                {"form": WirelessKeyInfoForm()},
            )
    except Exception as e:
        logger.error(
            f"An error occurred in the wireless key info form view: {e}", exc_info=True
        )
        return render(
            request,
            CYPH3R_500_ERROR_PAGE,
        )


@require_http_methods(["GET", "POST"])
def wireless_pgp_upload(request):
    """
    Validates uploaded PGP public keys
    Generates the secret key and wrap key
    Splits wrap key into key shares for 3 of 5 scheme
    Generates encrypted files for provider and security officers
    """
    try:
        # Check if the request is a POST request
        if request.method == "POST":

            # Populate the form with POST data and PGP public key files
            form = WirelessPGPUploadForm(request.POST, request.FILES)

            # Validate the form data
            if form.is_valid():
                # Retrieve key identifier, key size, protocol and key type from the session
                key_identifier = request.session["key_identifier"]
                key_size = int(request.session["key_size"])
                key_type = request.session["key_type"]
                protocol = request.session["protocol"]

                # Initialize CryptoManager for cryptographic operations
                cm = CryptoManager()

                # Generate the secret key as a random byte string of the given key size
                # Retrieve or generate the key and store in the cache
                secret_key = cache.get(f"secret_key_{request.session.session_key}")
                if not secret_key:
                    secret_key = cm.generate_random_key_bytes(key_size)
                    cache.set(
                        f"secret_key_{request.session.session_key}",
                        secret_key,
                        1800,
                    )

                # Update the database with the Key Generation information
                KeyGeneration.objects.create(
                    key_id=f"{key_type}_secret_key",
                    date_generated=datetime.now(),
                    key_size=key_size,
                    is_split=False,
                )

                # Generates a 128 bit wrap key
                # Split it into 5 shares using Shamir Secret Sharing (SSS)
                # These will be shared among 5 internal security officers (SO) for a 3 of 5 scheme
                wrap_key = cache.get(f"wrap_key_{request.session.session_key}")
                if not wrap_key:
                    wrap_key = cm.generate_random_key_bytes(128)
                    cache.set(
                        f"wrap_key_{request.session.session_key}",
                        wrap_key,
                        None,
                    )

                # Update the database with the Key Generation information
                wk = KeyGeneration.objects.create(
                    key_id=f"{key_type}_wrap_key",
                    date_generated=datetime.now(),
                    key_size=key_size,
                    is_split=True,
                )

                # Split the wrap key into 5 shares using Shamir Secret Sharing
                shares = cm.shamir_split_secret(3, 5, wrap_key)

                # Update the database with the Key Split information
                KeySplit.objects.create(key=wk, number_of_shares=5, type="SHAMIR")

                # Generate 12 bytes nonce for the AES-GCM encryption of the secret key by the wrap key
                nonce = cm.generate_random_key_bytes(96)

                # Encrypt the secret key using the wrap key and nonce
                wrapped_secret_key = cm.encrypt_with_aes_gcm(
                    wrap_key, nonce, secret_key
                )

                # Update the database with the file encryption information
                FileEncryption.objects.create(
                    key=wk,
                    encryption_algorithm="AES-GCM",
                    number_of_files_encrypted=1,
                )

                # Concatenate 12 bytes nonce + wrapped secret key
                # Nonce is required for AES GCM decryption
                wrapped_data = nonce + wrapped_secret_key

                # Check if user wants artifacts stored in GCP Storage Bucket
                gcp_storage = form.cleaned_data.get("upload_to_cloud_storage")

                # Initialize GCPManager object if user wants to write files to GCP Storage
                gcpm = (
                    GCPManager(
                        project_id=os.getenv("GCP_PROJECT_ID"),
                        storage_bucket=os.getenv("GCP_STORAGE_BUCKET"),
                    )
                    if gcp_storage
                    else None
                )

                # Use datetime to create unique blob path if file is to be written to GCP Storage
                datetime_format = (
                    datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
                    if gcp_storage
                    else None
                )

                # Calling helper function to write the encrypted secret key to a file and return the file name
                wrapped_secret_key_file = create_wireless_wrapped_secret_key_file(
                    cm,
                    gcpm,
                    wrapped_data,
                    protocol,
                    key_type,
                    key_identifier,
                    datetime_format,
                )
                # Store wrapped secret file path in session
                request.session["wrapped_secret_key_file"] = wrapped_secret_key_file

                # Calling helper function to generate PGP encrypted files for the external provider
                # Each file contains the XOR share of the secret key encrypted with a provider's PGP key
                # This returns a list of the file names of the encrypted provider files for download
                provider_files = create_wireless_provider_encrypted_key_files(
                    form,
                    cm,
                    secret_key,
                    key_size,
                    key_type,
                    protocol,
                    key_identifier,
                    number_of_shares=3,
                )
                # Store Provider file paths in session
                request.session["provider_files"] = provider_files

                # Update the database with the File encryption information
                FileEncryption.objects.create(
                    key=None,
                    encryption_algorithm="PGP",
                    number_of_files_encrypted=len(provider_files),
                )

                # Calling helper function to encrypt security officer (SO) files
                # Each file contains the Shamir wrap key share encrypted with a security officer's PGP key
                # This returns a list of the file names of the encrypted SO files for download
                security_officer_files = (
                    create_wireless_security_officers_encrypted_key_files(
                        form,
                        cm,
                        gcpm,
                        key_type,
                        key_identifier,
                        protocol,
                        shares,
                        datetime_format,
                    )
                )
                # Store SO file paths in session
                request.session["security_officer_files"] = security_officer_files

                # Update the database with the File encryption information
                FileEncryption.objects.create(
                    key=None,
                    encryption_algorithm="PGP",
                    number_of_files_encrypted=len(security_officer_files),
                )

                # Calling helper function to encrypt secret with Yubikey fallback PGP keys
                # This returns a list of the file names of the encrypted secrets for download
                fallback_yubikey_files = (
                    create_wireless_fallback_yubikey_encrypted_key_files(
                        form,
                        cm,
                        gcpm,
                        key_type,
                        key_identifier,
                        protocol,
                        secret_key,
                        datetime_format,
                    )
                )
                # Store SO file paths in session
                request.session["fallback_yubikey_files"] = fallback_yubikey_files

                # Update the database with the File encryption information
                FileEncryption.objects.create(
                    key=None,
                    encryption_algorithm="PGP",
                    number_of_files_encrypted=len(fallback_yubikey_files),
                )

                # Check if protocol is milenage
                # Check that the PGP key of the engineer that will be at the terminal was uploaded
                # This check is done to prevent tuak keys from being written using the PGP key of the engineer
                # Tuak keys will not be entered at a terminal and do not need to be exposed by a single person

                milenage_file = None  # Initialize the milenage file name to None
                if form.cleaned_data["milenage_public_key"] and protocol == "milenage":

                    # Calling helper function to create the encrypted milenage key file
                    # This returns the file name of the encrypted milenage key file for download
                    milenage_file = create_wireless_milenage_encrypted_file(
                        form, cm, secret_key, key_type, key_identifier
                    )

                    # Update the database with the File encryption information
                    FileEncryption.objects.create(
                        key=None,
                        encryption_algorithm="PGP",
                        number_of_files_encrypted=1,
                    )
                    # Store milenage file path in session
                    request.session["milenage_file"] = milenage_file

                # Clear secret and wrap key from cache
                cache.delete(f"secret_key_{request.session.session_key}")
                cache.delete(f"wrap_key_{request.session.session_key}")

                # Redirect to the key download page
                return redirect("wireless-key-download")
            else:
                # Render the PGP Upload form again with validation errors if the form is invalid
                return render(
                    request,
                    "cyph3r/wireless_templates/wireless-pgp-upload.html",
                    {"form": form},
                )
        else:
            # Initialize the form with the PGP Upload form
            form = WirelessPGPUploadForm()
            # Return the PGP Upload form
            return render(
                request,
                "cyph3r/wireless_templates/wireless-pgp-upload.html",
                {"form": form},
            )
    except Exception as e:
        logger.error(
            f"An error occurred in the wireless generate key view: {e}", exc_info=True
        )
        return render(
            request,
            CYPH3R_500_ERROR_PAGE,
        )


@require_http_methods(["GET"])
def wireless_key_download(request):
    """
    Returns download page for wireless keys
    """
    try:
        # Get the file paths from the session
        security_officer_files = request.session.get("security_officer_files")
        fallback_yubikey_files = request.session.get("fallback_yubikey_files")
        provider_files = request.session.get("provider_files")
        wrapped_secret_key_file = request.session.get("wrapped_secret_key_file")
        if request.session.get("milenage_file"):
            milenage_file = request.session.get("milenage_file")

        # Add file path to be downloaded to the context
        downloadable_files = (
            {
                "security_officer_files": security_officer_files,
                "provider_files": provider_files,
                "fallback_yubikey_files": fallback_yubikey_files,
                "wrapped_secret_key_file": wrapped_secret_key_file,
                "milenage_file": milenage_file,
            }
            if request.session.get("milenage_file")
            else {
                "security_officer_files": security_officer_files,
                "provider_files": provider_files,
                "fallback_yubikey_files": fallback_yubikey_files,
                "wrapped_secret_key_file": wrapped_secret_key_file,
            }
        )
        return render(
            request,
            "cyph3r/wireless_templates/wireless-key-download.html",
            downloadable_files,
        )
    except Exception as e:
        logger.error(
            f"An error occurred in the wireless key download view: {e}", exc_info=True
        )
        return render(
            request,
            CYPH3R_500_ERROR_PAGE,
        )


####################
# Token Generation #
####################


@require_http_methods(["GET", "POST"])
def token_gen_info(request):
    """
    Returns Token Generation Info Page
    """
    try:
        # Remove any existing key share session key to ensure that session is clean and has no stale data.

        # Check if the request is a POST request
        if request.method == "POST":

            # Populate the form with POST data and PGP public key files
            form = TokenGenerationForm(request.POST, request.FILES)

            # Validate the form data
            if form.is_valid():
                # Ensure that the session is created.
                if not request.session.session_key:
                    request.session.create()

                # Clear any stale session data
                request.session.pop("token_generated", None)
                request.session.pop("token_type", None)

                # Initialize the CryptoManager
                cm = CryptoManager()

                # Generate the token based on the user's selection
                if form.cleaned_data.get("token") == "key":
                    key_size = form.cleaned_data.get("token_length")
                    token = cm.generate_random_key_hex(int(key_size))

                    # Update the database with the Key Generation information
                    KeyGeneration.objects.create(
                        key_id="generated_key_token",
                        date_generated=datetime.now(),
                        key_size=key_size,
                        is_split=False,
                    )

                elif form.cleaned_data.get("token") == "url":
                    url_length = form.cleaned_data.get("token_length")
                    token = cm.generate_url_safe_string(int(url_length))

                elif form.cleaned_data.get("token") == "password":
                    password_length = form.cleaned_data.get("password_length")
                    special = form.cleaned_data.get("special_chars")
                    digits = form.cleaned_data.get("digits")
                    uppercase = form.cleaned_data.get("uppercase")
                    lowercase = form.cleaned_data.get("lowercase")
                    token = cm.generate_password(
                        password_length,
                        special=special,
                        digits=digits,
                        uppercase=uppercase,
                        lowercase=lowercase,
                    )
                request.session["token_generated"] = token
                request.session["token_type"] = form.cleaned_data.get("token")

                return redirect("token-gen-result")

            else:
                return render(
                    request,
                    "cyph3r/token_gen_templates/token-gen-info.html",
                    {"form": form},
                )
        else:
            form = TokenGenerationForm()
            return render(
                request,
                "cyph3r/token_gen_templates/token-gen-info.html",
                {"form": form},
            )
    except Exception as e:
        logger.error(
            f"An error occurred in the token generation info view: {e}", exc_info=True
        )
        return render(
            request,
            CYPH3R_500_ERROR_PAGE,
        )


@require_http_methods(["GET"])
def token_gen_result(request):
    """
    Returns Generated Token selected by user
    """
    try:
        token = request.session.get("token_generated")
        token_type = request.session.get("token_type")

        # Return the token generation result page
        return render(
            request,
            "cyph3r/token_gen_templates/token-gen-result.html",
            {"token": token, "token_type": token_type},
        )
    except Exception as e:
        logger.error(f"An error occurred in token gen result view: {e}", exc_info=True)
        return render(
            request,
            CYPH3R_500_ERROR_PAGE,
        )
