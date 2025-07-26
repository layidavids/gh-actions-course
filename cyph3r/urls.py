from django.urls import path
from . import views

"""
This module contains the URL patterns for the cyph3r app.

"""

urlpatterns = [
    # Index page
    path("", views.index, name="index"),
    # Wireless pages
    path(
        "wireless-ceremony-intro/",
        views.wireless_ceremony_intro,
        name="wireless-ceremony-intro",
    ),
    path(
        "wireless-key-info/",
        views.wireless_key_info,
        name="wireless-key-info",
    ),
    path(
        "wireless-key-download/",
        views.wireless_key_download,
        name="wireless-key-download",
    ),
    path(
        "wireless-pgp-upload/",
        views.wireless_pgp_upload,
        name="wireless-pgp-upload",
    ),
    # Key Share pages
    path("key-share-info/", views.key_share_info, name="key-share-info"),
    path(
        "key-share-reconstruct/",
        views.key_share_reconstruct,
        name="key-share-reconstruct",
    ),
    path(
        "key-share-split/",
        views.key_share_split,
        name="key-share-split",
    ),
    path("key-share-download/", views.key_share_download, name="key-share-download"),
    path("key-share-result/", views.key_share_result, name="key-share-result"),
    path("key-share-intro/", views.key_share_intro, name="key-share-intro"),
    # Data Protect pages
    path("data-protect-intro/", views.data_protect_intro, name="data-protect-intro"),
    path("data-protect-info/", views.data_protect_info, name="data-protect-info"),
    path(
        "data-protect-download/",
        views.data_protect_download,
        name="data-protect-download",
    ),
    path("data-protect-result/", views.data_protect_result, name="data-protect-result"),
    # Token Gen Info
    path("token-gen-info/", views.token_gen_info, name="token-gen-info"),
    path("token-gen-result/", views.token_gen_result, name="token-gen-result"),
]
