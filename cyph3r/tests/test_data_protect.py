from django.test import Client
import pytest
import os
from django.conf import settings
from cyph3r.crypto import CryptoManager
from test_helpers_dataprotect import (
    validate_data_protect_info_post_response,
)


def test_data_protect_info(
    client: Client,
    data_protect_info_html_page: str,
    data_protect_url: str,
):
    """
    Test that the Data Protect info page view renders correctly.
    """
    response = client.get(data_protect_url)
    assert response.status_code == 200
    assert data_protect_info_html_page in [t.name for t in response.templates]


@pytest.mark.django_db
def test_data_protect_post_long_hex_response(
    cleanup_generated_files: None,
    client: Client,
    data_protect_url: str,
    data_protect_info_html_page: str,
    data_protect_post_long_hex_string: dict,
):
    """
    Test app invalidates keys that are not 128/192/256 bits.
    """
    # Post bad PGP public keys and validate the response
    response = validate_data_protect_info_post_response(
        client,
        data_protect_url,
        data_protect_post_long_hex_string,
        data_protect_info_html_page,
    )
    assert response.context["form"]["aead_key"].errors == [
        "Value must be either 128 | 192 | 256 bits."
    ]


@pytest.mark.django_db
def test_data_protect_post_bad_hex_response(
    cleanup_generated_files: None,
    client: Client,
    data_protect_url: str,
    data_protect_info_html_page: str,
    data_protect_post_bad_hex_string: dict,
):
    """
    Test app invalidates keys that are non-hexadecimal.
    """
    # Post bad PGP public keys and validate the response
    response = validate_data_protect_info_post_response(
        client,
        data_protect_url,
        data_protect_post_bad_hex_string,
        data_protect_info_html_page,
    )
    assert response.context["form"]["aead_key"].errors == [
        "Value must be a hexadecimal string."
    ]


@pytest.mark.django_db
def test_data_protect_post_enablepgp_and_no_pgp_key(
    cleanup_generated_files: None,
    client: Client,
    data_protect_url: str,
    data_protect_info_html_page: str,
    data_protect_post_enable_pgp_encrypt_no_publickeys: dict,
):
    """
    Test app returns errors when pgp_encrypt is enabled with no public keys uploaded.
    """
    response = validate_data_protect_info_post_response(
        client,
        data_protect_url,
        data_protect_post_enable_pgp_encrypt_no_publickeys,
        data_protect_info_html_page,
    )
    assert response.context["form"]["public_key"].errors == ["Upload a public key."]
    assert response.context["form"]["name"].errors == ["Provide a name."]


@pytest.mark.django_db
def test_data_protect_post_bad_chacha_key_response(
    cleanup_generated_files: None,
    client: Client,
    data_protect_url: str,
    data_protect_info_html_page: str,
    data_protect_post_128key_chacha_string: dict,
):
    """
    Test app invalidates chacha keys that are not 256 bits.
    """
    # Post bad PGP public keys and validate the response
    response = validate_data_protect_info_post_response(
        client,
        data_protect_url,
        data_protect_post_128key_chacha_string,
        data_protect_info_html_page,
    )
    assert response.context["form"]["aead_key"].errors == [
        "ChaCha20-Poly1305 supports only 256 bit keys."
    ]


@pytest.mark.django_db
def test_data_protect_gcm_post_response(
    cleanup_generated_files: None,
    cm: CryptoManager,
    client: Client,
    data_protect_url: str,
    data_protect_download_html_page: str,
    data_protect_gcm_encrypt_post_data_pgp: dict,
):
    """
    Post to data protect info view with AES-GCM encryption request + PGP Keys and validate the response
    """
    response = validate_data_protect_info_post_response(
        client,
        data_protect_url,
        data_protect_gcm_encrypt_post_data_pgp,
        data_protect_download_html_page,
    )
    # Decrypt and validate the result
    with open(
        os.path.join(
            settings.MEDIA_ROOT,
            client.session.session_key,
            response.context["data_protect_file"],
        ),
        "rb",
    ) as f:
        encrypted_data = f.read()
        decrypted_data = cm.gpg.decrypt(encrypted_data)

    assert decrypted_data.ok == True

    # Get the AEAD Key
    aead_key = cm.hex_to_bytes("5b5239115089e0f9678ea6e49ef07b6a")

    # Extract the nonce and ciphertext from the decrypted data
    ct_hex = decrypted_data.data.split(b"\n")[6].split(b" ")[1].decode("utf-8")
    nonce_hex = decrypted_data.data.split(b"\n")[2].split(b" ")[1].decode("utf-8")
    aad = decrypted_data.data.split(b"\n")[4].split(b" ")[1]

    # Decrypt the ciphertext
    pt = cm.decrypt_with_aes_gcm(
        aead_key, cm.hex_to_bytes(nonce_hex), cm.hex_to_bytes(ct_hex), aad
    )
    assert cm.bytes_to_utf8(pt) == "cyph3r"


@pytest.mark.django_db
def test_data_protect_chacha_post_response(
    cleanup_generated_files: None,
    cm: CryptoManager,
    client: Client,
    data_protect_url: str,
    data_protect_result_html_page: str,
    data_protect_chacha_encrypt_post_data_nopgp: dict,
):
    """
    Post to data protect info view with Chacha20 encryption and validate the response
    """
    response = validate_data_protect_info_post_response(
        client,
        data_protect_url,
        data_protect_chacha_encrypt_post_data_nopgp,
        data_protect_result_html_page,
    )

    # Get the AEAD Key
    aead_key = cm.hex_to_bytes(
        "8b7a760f18c47d98f6428416c37c50141e1614e2f78211e7e6cc027325456e28"
    )

    # Get the result on the response and decrypt the ciphertext
    result = response.context["operation_output"]
    ct = cm.hex_to_bytes((result["aead_output"]))
    nonce = cm.hex_to_bytes(result["nonce"])
    aad = result["aad"].encode("utf-8")
    pt = cm.decrypt_with_chacha20_poly1305(aead_key, nonce, ct, aad)
    assert cm.bytes_to_utf8(pt) == "cyph3r"
