from django.conf import settings

"""
Helper functions for testing key sharing views.

"""


def validate_key_share_info_post_response(
    client,
    request_url,
    post_data,
    html_page,
    validate_session_data=True,
):
    """
    Helper function to validate response and client session after posting key share info form data to key-share-info view.
    """
    # The key share info view redirect users to either reconsruct or split key views
    response = client.post(request_url, post_data, format="multipart", follow=True)
    assert response.status_code == 200
    assert html_page in [t.name for t in response.templates]
    if validate_session_data:
        for key, value in post_data.items():
            if key == "key_share_public_keys":
                pass  # Ignore key_share_public_keys for the key-share-flow for now since files cannot be stored in the session
            else:
                assert client.session[key] == value
        if client.session["pgp_encrypt"]:
            # Assert public key files are written to disk
            assert client.session["public_key_files"] is not None
    return response


def validate_key_reconstruction_bad_post_response(client, url, html_page, post_data):
    """
    Helper function to validate bad response when invalid hex string is provided.
    """
    # client posts "key index/key share" with invalid hex string
    response = client.post(url, post_data, follow=True)
    assert response.status_code == 200
    assert html_page in [t.name for t in response.templates]
    return response


def validate_key_reconstruction_post_response(
    client, url, html_page_reconstruct, html_page_download, post_data, key_share_count
):
    """
    Helper function to validate response and client session after posting xor/shamir reconstruction form data to key-share-reconstruct view.
    """
    # client posts "key index/key share" a number of times determined by "key_share_count" parameter to simulate Security Officers posting their key shares
    for i in range(0, key_share_count):
        assert client.session["submitted_officer_count"] == i + 1
        response = client.post(url, post_data[i], follow=True)
        assert response.status_code == 200
        # Check that the download page is displayed after the last post, otherwise continue displaying the reconstruction page
        if i == key_share_count - 1:
            assert html_page_download in [t.name for t in response.templates]
        else:
            assert html_page_reconstruct in [t.name for t in response.templates]
    if client.session["pgp_encrypt"]:
        assert client.session["public_key_files"] is not None
    return response


def validate_key_split_post_response(client, url, html_page_result, post_data):
    """
    Helper function to validate response and client session after posting form to the key-share-split view.
    """
    # client posts key for splitting
    response = client.post(url, post_data, follow=True)
    assert response.status_code == 200
    # Check that the result page is displayed after the last post, otherwise continue displaying the reconstruction page
    assert html_page_result in [t.name for t in response.templates]
    return response


def get_key_share_secret_key_and_validate(cm, client, response, secret_key):
    """
    Helper function to get reconstructed secret key and validate it is the right key.
    """
    # Access downloaded file and decrypt to get the secret key
    for file_name in response.context["secret_files"]:
        encrypted_secret_file_location = (
            settings.MEDIA_ROOT / client.session.session_key / file_name
        )
        with open(encrypted_secret_file_location, "rb") as f:
            encrypted_secret = f.read()
            decrypted_secret = cm.gpg.decrypt(encrypted_secret)

            # Check that the decryption was successful
            assert decrypted_secret.ok == True

    # Check that the decrypted secret key is the same secret key used to create the key shares
    assert decrypted_secret.data.decode() == secret_key
