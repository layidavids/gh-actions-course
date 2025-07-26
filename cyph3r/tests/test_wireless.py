import pytest
from django.urls import reverse
from test_helpers_wireless import (
    validate_post_response,
    validate_response_context,
    process_provider_keys,
    process_milenage_keys,
    process_yubikey_fallback_keys,
    process_security_officer_wrap_keys,
    get_wrapped_secret_key,
)


def test_wireless_view(client):
    """
    Test that the wireless intro view renders correctly.
    """
    url = reverse("wireless-ceremony-intro")
    response = client.get(url)
    assert response.status_code == 200
    assert "cyph3r/wireless_templates/wireless-ceremony-intro.html" in [
        t.name for t in response.templates
    ]


@pytest.mark.django_db
def test_wireless_key_generation_milenage_op_keys(
    cleanup_generated_files,
    cm,
    client,
    pgp_public_keys,
    bad_pgp_public_keys,
    key_info_milenage_op_post_data,
    pgp_upload_url,
    pgp_upload_html_page,
    wireless_key_info_url,
    wireless_key_download_html_page,
):
    """
    Test for milenage op keys
    Test that the wireless_gcp_storage_form view renders correctly and validates data.
    Test that the wireless_pgp_upload_form view renders correctly and validates data.
    Test that all session data is stored correctly.
    Test that the secret key is the same for the provider, security officers and the terminal engineer.
    """

    # Post the key information data to the view and validate the response
    validate_post_response(
        client,
        wireless_key_info_url,
        key_info_milenage_op_post_data,
        pgp_upload_html_page,
    )

    # Post/upload bad public keys to the view and validate the response
    bad_response = validate_post_response(
        client,
        pgp_upload_url,
        bad_pgp_public_keys,
        pgp_upload_html_page,
        validate_session_data=False,
    )

    assert (
        len(bad_response.context["form"]["security_officers_public_keys"].errors) == 3
    )
    assert len(bad_response.context["form"]["provider_public_keys"].errors) == 3
    assert len(bad_response.context["form"]["milenage_public_key"].errors) == 3

    # Post/upload valid public keys to the view and validate the response
    response = validate_post_response(
        client,
        pgp_upload_url,
        pgp_public_keys,
        wireless_key_download_html_page,
        validate_session_data=False,
    )
    # Check that the response context is passed correctly
    validate_response_context(client, response)

    # Process the provider keys
    provider_secret_key = process_provider_keys(cm, response)

    # Process the Milenage keys
    milenage_secret_key = process_milenage_keys(cm, response)

    # Process the Fallback keys
    fallback_yubi_secret_key = process_yubikey_fallback_keys(cm, response)

    # Assert the milenage, fallback key and provider secret keys are the same
    assert milenage_secret_key == provider_secret_key
    assert milenage_secret_key == fallback_yubi_secret_key

    # Process the security officer wrap keys
    wrap_key = process_security_officer_wrap_keys(cm, response)

    # Get nonce and wrapped secret key
    nonce, ciphertext = get_wrapped_secret_key(cm, response)

    # Decrypt the wrapped secret key with the wrap key
    decrypted_secret_key = cm.decrypt_with_aes_gcm(wrap_key, nonce, ciphertext)

    # Assert the decrypted secret key is the same as the provider secret key and mileange secret key
    assert (
        decrypted_secret_key
        == cm.hex_to_bytes(provider_secret_key)
        == cm.hex_to_bytes(milenage_secret_key)
        == cm.hex_to_bytes(fallback_yubi_secret_key)
    )


@pytest.mark.django_db
def test_wireless_key_generation_milenage_transport_keys(
    cleanup_generated_files,
    cm,
    client,
    pgp_public_keys,
    key_info_milenage_transport_post_data,
    pgp_upload_url,
    pgp_upload_html_page,
    wireless_key_info_url,
    wireless_key_download_html_page,
):
    """
    Test for milenage transport keys
    Test that the wireless_gcp_storage_form view renders correctly and validates data.
    Test that the wireless_pgp_upload_form view renders correctly and validates data.
    Test that all session data is stored correctly.
    Test that the secret key is the same for the provider, security officers and the terminal engineer.
    """

    # Post the key information data to the view and validate the response
    validate_post_response(
        client,
        wireless_key_info_url,
        key_info_milenage_transport_post_data,
        pgp_upload_html_page,
    )

    # Post/upload the public keys to the view and validate the response
    response = validate_post_response(
        client,
        pgp_upload_url,
        pgp_public_keys,
        wireless_key_download_html_page,
        validate_session_data=False,
    )
    # Check that the response context is passed correctly
    validate_response_context(client, response)

    # Process the provider keys
    provider_secret_key = process_provider_keys(cm, response)

    # Process the Milenage keys
    milenage_secret_key = process_milenage_keys(cm, response)

    # Process the Fallback keys
    fallback_yubi_secret_key = process_yubikey_fallback_keys(cm, response)

    # Assert the milenage, fallback and provider secret keys are the same
    assert milenage_secret_key == provider_secret_key
    assert milenage_secret_key == fallback_yubi_secret_key

    # Process the security officer wrap keys
    wrap_key = process_security_officer_wrap_keys(cm, response)

    # Get nonce and wrapped secret key
    nonce, ciphertext = get_wrapped_secret_key(cm, response)

    # Decrypt the wrapped secret key with the wrap key
    decrypted_secret_key = cm.decrypt_with_aes_gcm(wrap_key, nonce, ciphertext)

    # Assert the decrypted secret key is the same as the provider secret key and mileange secret key
    assert (
        decrypted_secret_key
        == cm.hex_to_bytes(provider_secret_key)
        == cm.hex_to_bytes(milenage_secret_key)
    )


@pytest.mark.django_db
def test_wireless_key_generation_tuak_transport_keys(
    cleanup_generated_files,
    cm,
    client,
    pgp_public_keys,
    key_info_tuak_transport_post_data,
    pgp_upload_url,
    pgp_upload_html_page,
    wireless_key_info_url,
    wireless_key_download_html_page,
):
    """
    Test for tuak transport keys
    Test that the wireless_gcp_storage_form view renders correctly and validates data.
    Test that the wireless_pgp_upload_form view renders correctly and validates data.
    Test that all session data is stored correctly.
    Test that the secret key is the same for the provider and the security officers.
    """
    # Post the key information data to the view and validate the response
    validate_post_response(
        client,
        wireless_key_info_url,
        key_info_tuak_transport_post_data,
        pgp_upload_html_page,
    )
    # Post/upload the public keys to the view and validate the response
    response = validate_post_response(
        client,
        pgp_upload_url,
        pgp_public_keys,
        wireless_key_download_html_page,
        validate_session_data=False,
    )
    # Check that the response context is passed correctly
    validate_response_context(client, response)

    # Process the provider keys
    provider_secret_key = process_provider_keys(cm, response)

    # Process the Fallback keys
    fallback_yubi_secret_key = process_yubikey_fallback_keys(cm, response)

    # Assert the provider and fallback secret keys are the same
    assert provider_secret_key == fallback_yubi_secret_key

    # Process the security officer wrap keys
    wrap_key = process_security_officer_wrap_keys(cm, response)

    # Get nonce and wrapped secret key
    nonce, ciphertext = get_wrapped_secret_key(cm, response)

    # Decrypt the wrapped secret key with the wrap key
    decrypted_secret_key = cm.decrypt_with_aes_gcm(wrap_key, nonce, ciphertext)

    # Assert the decrypted secret key is the same as the provider secret key
    assert decrypted_secret_key == cm.hex_to_bytes(provider_secret_key)


@pytest.mark.django_db
def test_wireless_key_generation_tuak_op_keys(
    cleanup_generated_files,
    cm,
    client,
    pgp_public_keys,
    key_info_tuak_op_post_data,
    pgp_upload_url,
    pgp_upload_html_page,
    wireless_key_info_url,
    wireless_key_download_html_page,
):
    """
    Test for tuak op keys
    Test that the wireless_gcp_storage_form view renders correctly and validates data.
    Test that the wireless_pgp_upload_form view renders correctly and validates data.
    Test that all session data is stored correctly.
    Test that the secret key is the same for the provider and the security officers.
    """
    # Post the key information data to the view and validate the response
    validate_post_response(
        client,
        wireless_key_info_url,
        key_info_tuak_op_post_data,
        pgp_upload_html_page,
    )

    # Post/upload the public keys to the view and validate the response
    response = validate_post_response(
        client,
        pgp_upload_url,
        pgp_public_keys,
        wireless_key_download_html_page,
        validate_session_data=False,
    )
    # Check that the response context is passed correctly
    validate_response_context(client, response)

    # Process the provider keys
    provider_secret_key = process_provider_keys(cm, response)

    # Process the Fallback keys
    fallback_yubi_secret_key = process_yubikey_fallback_keys(cm, response)

    # Assert the provider and fallback secret keys are the same
    assert provider_secret_key == fallback_yubi_secret_key

    # Process the security officer wrap keys
    wrap_key = process_security_officer_wrap_keys(cm, response)

    # Get nonce and wrapped secret key
    nonce, ciphertext = get_wrapped_secret_key(cm, response)

    # Decrypt the wrapped secret key with the wrap key
    decrypted_secret_key = cm.decrypt_with_aes_gcm(wrap_key, nonce, ciphertext)

    # Assert the decrypted secret key is the same as the provider secret key
    assert decrypted_secret_key == cm.hex_to_bytes(provider_secret_key)
