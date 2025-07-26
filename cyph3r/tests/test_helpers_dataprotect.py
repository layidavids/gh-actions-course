from django.conf import settings

"""
Helper functions for testing data protect views.

"""


def validate_data_protect_info_post_response(
    client,
    request_url,
    post_data,
    html_page,
):
    """
    Helper function to validate response and client session after posting key share info form data to key-share-info view.
    """
    # The key share info view redirect users to either reconsruct or split key views
    response = client.post(request_url, post_data, format="multipart", follow=True)
    assert response.status_code == 200
    assert html_page in [t.name for t in response.templates]
    return response
