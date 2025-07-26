from typing import Literal
from django.test import Client
import pytest
from django.urls import reverse
from cyph3r.crypto import CryptoManager
from test_helpers_keyshare import (
    validate_key_share_info_post_response,
    validate_key_reconstruction_post_response,
    validate_key_split_post_response,
    get_key_share_secret_key_and_validate,
)


def test_key_share_info(
    client: Client,
    key_share_info_html_page: str,
    key_share_info_url: str,
):
    """
    Test that the key share info view renders correctly.
    """
    response = client.get(key_share_info_url)
    assert response.status_code == 200
    assert key_share_info_html_page in [t.name for t in response.templates]


@pytest.mark.django_db
def test_key_share_post_invalid_public_keys(
    cleanup_generated_files: None,
    cm: CryptoManager,
    client: Client,
    key_share_info_url: str,
    key_share_info_html_page: str,
    key_share_info_post_bad_data: dict,
):
    """
    Test app invalidates non-PGP public files.
    """
    # Post bad PGP public keys and validate the response
    bad_response = validate_key_share_info_post_response(
        client,
        key_share_info_url,
        key_share_info_post_bad_data,
        key_share_info_html_page,
        validate_session_data=False,
    )
    # Validate that the form reports 3 errors related to the bad PGP public keys
    assert len(bad_response.context["form"]["key_share_public_keys"].errors) == 3


@pytest.mark.django_db
def test_key_share_shamir_reconstruction(
    cleanup_generated_files: None,
    cm: CryptoManager,
    client: Client,
    key_share_info_url: str,
    key_share_reconstruct_url: str,
    key_share_reconstruct_html_page: str,
    key_share_download_html_page: str,
    key_share_info_shamir_reconstruct_post_data: dict,
    key_share_reconstruct_shamir_post_data: list[dict],
    key_share_shamir_secret_key: str,
):
    """
    Test that shamir key reconstruction flow is successful.
    """

    # Post the key information data to the view and validate the response
    validate_key_share_info_post_response(
        client,
        key_share_info_url,
        key_share_info_shamir_reconstruct_post_data,
        key_share_reconstruct_html_page,
    )

    response = validate_key_reconstruction_post_response(
        client,
        key_share_reconstruct_url,
        key_share_reconstruct_html_page,
        key_share_download_html_page,
        key_share_reconstruct_shamir_post_data,
        key_share_count=3,
    )

    get_key_share_secret_key_and_validate(
        cm, client, response, key_share_shamir_secret_key
    )


@pytest.mark.django_db
def test_key_share_xor_reconstruction(
    cleanup_generated_files: None,
    cm: CryptoManager,
    client: Client,
    key_share_info_url: str,
    key_share_reconstruct_url: str,
    key_share_reconstruct_html_page: str,
    key_share_download_html_page: str,
    key_share_info_xor_reconstruct_post_data: dict,
    key_share_reconstruct_xor_post_data: list[dict],
    key_share_xor_secret_key: str,
):
    """
    Test that xor key reconstruction is successful.
    """
    # Post the key information data to the view and validate the response
    validate_key_share_info_post_response(
        client,
        key_share_info_url,
        key_share_info_xor_reconstruct_post_data,
        key_share_reconstruct_html_page,
    )

    response = validate_key_reconstruction_post_response(
        client,
        key_share_reconstruct_url,
        key_share_reconstruct_html_page,
        key_share_download_html_page,
        key_share_reconstruct_xor_post_data,
        key_share_count=5,
    )

    get_key_share_secret_key_and_validate(
        cm, client, response, key_share_xor_secret_key
    )


@pytest.mark.django_db
def test_key_share_xor_split(
    cleanup_generated_files: None,
    cm: CryptoManager,
    client: Client,
    key_share_info_url: str,
    key_share_split_url: str,
    key_share_split_html_page: str,
    key_share_result_html_page: str,
    key_share_info_xor_split_post_data: dict,
    key_share_split_xor_secret_key_post_data: str,
):
    """
    Test that xor key split/reconstruction is successful.
    """
    # Post the key information data to the view and validate the response
    validate_key_share_info_post_response(
        client,
        key_share_info_url,
        key_share_info_xor_split_post_data,
        key_share_split_html_page,
    )

    response = validate_key_split_post_response(
        client,
        key_share_split_url,
        key_share_result_html_page,
        key_share_split_xor_secret_key_post_data,
    )
    # Get all the split keys and validate the secret key
    key_list = [
        cm.hex_to_bytes(key_share) for key_share in response.context["key_list"]
    ]

    assert (
        cm.bytes_to_hex(cm.xor_reconstruct_secret(key_list))
        == key_share_split_xor_secret_key_post_data["key"]
    )


@pytest.mark.django_db
def test_key_share_shamir_split(
    cleanup_generated_files: None,
    cm: CryptoManager,
    client: Client,
    key_share_info_url: str,
    key_share_split_url: str,
    key_share_split_html_page: str,
    key_share_result_html_page: str,
    key_share_info_shamir_split_post_data: dict,
    key_share_split_shamir_secret_key_post_data: str,
):
    """
    Test that shamir key split/reconstruction is successful.
    """
    # Post the key information data to the view and validate the response
    validate_key_share_info_post_response(
        client,
        key_share_info_url,
        key_share_info_shamir_split_post_data,
        key_share_split_html_page,
    )

    response = validate_key_split_post_response(
        client,
        key_share_split_url,
        key_share_result_html_page,
        key_share_split_shamir_secret_key_post_data,
    )
    # Get all the split keys and validate the secret key
    key_list = [
        (idx, cm.hex_to_bytes(key_share))
        for idx, key_share in response.context["key_list"]
    ]

    assert (
        cm.bytes_to_hex(cm.shamir_reconstruct_secret(key_list))
        == key_share_split_shamir_secret_key_post_data["key"]
    )
