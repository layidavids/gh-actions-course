import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from cyph3r.crypto import CryptoManager
from django.urls import reverse
from django.conf import settings
import shutil
import random
import copy
import os


######################
#  General Fixtures  #
######################


@pytest.fixture
def cm():
    """
    Fixture to return a CryptoManager instance.
    """
    # Get the path to the test PGP keys
    gnupghome = settings.BASE_DIR / "cyph3r" / "tests" / "pgp_test_keys"
    return CryptoManager(gnupghome)


@pytest.fixture
def cleanup_generated_files():
    """
    Fixture to cleanup generated files or folders.
    """
    yield
    # Cleanup generated files
    for f in os.listdir(settings.MEDIA_ROOT):
        path = os.path.join(settings.MEDIA_ROOT, f)
        if os.path.isdir(path):
            shutil.rmtree(path)
        else:
            os.remove(path)


@pytest.fixture
def pgp_public_keys():
    """
    Fixture to return PGP public key files for testing.
    """
    test_public_keys_dir = (
        settings.BASE_DIR / "cyph3r" / "tests" / "exported_public_keys"
    )

    # Read public keys from disk
    with open(
        test_public_keys_dir / "so1_1C45D386C0FA1F0E_pubkey.asc", "rb"
    ) as fso1, open(
        test_public_keys_dir / "so2_1302D17D7AB89284_pubkey.asc", "rb"
    ) as fso2, open(
        test_public_keys_dir / "so3_8E4DF0BC6678F086_pubkey.asc", "rb"
    ) as fso3, open(
        test_public_keys_dir / "so4_52BD7A5DBC58679C_pubkey.asc", "rb"
    ) as fso4, open(
        test_public_keys_dir / "so5_312E10617099212D_pubkey.asc", "rb"
    ) as fso5, open(
        test_public_keys_dir / "p1_36A7F867D02348E2_pubkey.asc", "rb"
    ) as fp1, open(
        test_public_keys_dir / "p2_004B67CF5F45143D_pubkey.asc", "rb"
    ) as fp2, open(
        test_public_keys_dir / "p3_6190B90847840025_pubkey.asc", "rb"
    ) as fp3, open(
        test_public_keys_dir / "m1_FF18092361401CF1_pubkey.asc", "rb"
    ) as fm1, open(
        test_public_keys_dir / "ybk1_BB9D6828703D7362_pubkey.asc", "rb"
    ) as fyk1, open(
        test_public_keys_dir / "ybk2_243A309C88A8FE47_pubkey.asc", "rb"
    ) as fyk2:
        so1 = SimpleUploadedFile("so1_1C45D386C0FA1F0E_pubkey.asc", fso1.read())
        so2 = SimpleUploadedFile("so2_1302D17D7AB89284_pubkey.asc", fso2.read())
        so3 = SimpleUploadedFile("so3_8E4DF0BC6678F086_pubkey.asc", fso3.read())
        so4 = SimpleUploadedFile("so4_52BD7A5DBC58679C_pubkey.asc", fso4.read())
        so5 = SimpleUploadedFile("so5_312E10617099212D_pubkey.asc", fso5.read())
        p1 = SimpleUploadedFile("p1_36A7F867D02348E2_pubkey.asc", fp1.read())
        p2 = SimpleUploadedFile("p2_004B67CF5F45143D_pubkey.asc", fp2.read())
        p3 = SimpleUploadedFile("p3_6190B90847840025_pubkey.asc", fp3.read())
        m1 = SimpleUploadedFile("m1_FF18092361401CF1_pubkey.asc", fm1.read())
        ybk1 = SimpleUploadedFile("ybk1_BB9D6828703D7362_pubkey.asc", fyk1.read())
        ybk2 = SimpleUploadedFile("ybk2_243A309C88A8FE47_pubkey.asc", fyk2.read())

    # Create dictionary for uploaded files
    pgp_file_uploads = {
        "security_officers_public_keys": [so1, so2, so3, so4, so5],
        "provider_public_keys": [p1, p2, p3],
        "fallback_public_keys": [ybk1, ybk2],
        "milenage_public_key": m1,
        "upload_to_cloud_storage": False,
    }

    return pgp_file_uploads


@pytest.fixture
def bad_pgp_public_keys(pgp_public_keys):
    """
    Fixture to return ineligible PGP public key files for testing.
    """
    test_public_keys_dir = (
        settings.BASE_DIR / "cyph3r" / "tests" / "exported_public_keys"
    )

    # Read public keys from disk
    with open(test_public_keys_dir / "alex.jpg", "rb") as fbad1, open(
        test_public_keys_dir / "loremipsum.txt", "rb"
    ) as fbad2, open(test_public_keys_dir / "hxx.jpg", "rb") as fbad3, open(
        test_public_keys_dir / "key.png", "rb"
    ) as fbad4, open(
        test_public_keys_dir / "otp2.webp", "rb"
    ) as fbad5:
        badpgp1 = SimpleUploadedFile("alex.jpg", fbad1.read())
        badpgp2 = SimpleUploadedFile("loremipsum.txt", fbad2.read())
        badpgp3 = SimpleUploadedFile("hxx.jpg", fbad3.read())
        badpgp4 = SimpleUploadedFile("key.png", fbad4.read())
        badpgp5 = SimpleUploadedFile("otp2.webp", fbad5.read())

    bad_pgp_file_uploads = copy.deepcopy(pgp_public_keys)
    bad_pgp_file_uploads["provider_public_keys"][1] = badpgp2
    bad_pgp_file_uploads["milenage_public_key"] = badpgp3
    bad_pgp_file_uploads["security_officers_public_keys"][1] = badpgp1

    return bad_pgp_file_uploads


#######################
#  Key Share Fixtures #
#######################


@pytest.fixture
def key_share_info_post_bad_data(bad_pgp_public_keys):
    """
    Fixture to return invalid values for Shamir Key Reconstruction.
    """
    return {
        "scheme": "shamir",
        "key_task": "reconstruct",
        "threshold_count": 3,
        "pgp_encrypt": True,
        "key_share_public_keys": [bad_pgp_public_keys["milenage_public_key"]],
    }


@pytest.fixture
def key_share_info_shamir_reconstruct_post_data(pgp_public_keys):
    """
    Fixture to return key information data for Shamir Key Reconstruction.
    """
    return {
        "scheme": "shamir",
        "key_task": "reconstruct",
        "threshold_count": 3,
        "pgp_encrypt": True,
        "key_share_public_keys": [pgp_public_keys["milenage_public_key"]],
    }


@pytest.fixture
def key_share_info_xor_reconstruct_post_data(pgp_public_keys):
    """
    Fixture to return key information data for Xor Key Reconstruction.
    """
    return {
        "scheme": "xor",
        "key_task": "reconstruct",
        "share_count": 5,
        "pgp_encrypt": True,
        "key_share_public_keys": [pgp_public_keys["milenage_public_key"]],
    }


@pytest.fixture
def key_share_reconstruct_shamir_key_shares():
    """
    Fixture to return 3 key shares for reconstructing shamir secret (3 of 5 scheme).
    """
    shamir_key_shares = [
        (1, "e0a387b8443b1a859b36b1b713d8a734"),
        (2, "df4b4059f3de64e74cd6021d101accc0"),
        (3, "64bafef0e76c9e9bb06e154e9d32109e"),
        (4, "9c88dbea3eef2b5a799dc66dd1c92b74"),
        (5, "277965432a5dd1268525d13e5ce1f72a"),
    ]
    # randomly select 3 shares
    return random.sample(shamir_key_shares, 3)


@pytest.fixture
def key_share_info_xor_split_post_data():
    """
    Fixture to post key information data for Xor Key Split.
    """
    return {
        "scheme": "xor",
        "key_task": "split",
        "share_count": 5,
        "pgp_encrypt": False,
    }


@pytest.fixture
def key_share_info_shamir_split_post_data():
    """
    Fixture to post key information data for Xor Key Split.
    """
    return {
        "scheme": "shamir",
        "key_task": "split",
        "share_count": 5,
        "threshold_count": 3,
        "pgp_encrypt": False,
    }


@pytest.fixture
def key_share_reconstruct_shamir_post_data(key_share_reconstruct_shamir_key_shares):
    """
    Fixture to return key information data for Shamir Key Reconstruction.
    """
    return [
        {"key_index": idx, "key_share": share}
        for idx, share in key_share_reconstruct_shamir_key_shares
    ]


@pytest.fixture
def key_share_reconstruct_xor_key_shares():
    """
    Fixture to return 5key shares for reconstructing xor secret.
    """
    xor_key_shares = [
        "29a2ca11c4613a8ae5d529e1d2f7383129ee9fb1f0dec93e31393cf2d6aa15cc",
        "4a5c0c7722e911a6bb32ffb85f7daa5e8f2d439a81ccf446ca2f74dcd56dacf0",
        "5637ba92b43b070ec90b21e561dd8e691a266d06a6b484670aa83b6402f59af6",
        "966383194fbf4d0d18b3e7b73a62bf22608101c5effbba40dd5b10fe515fc8b3",
        "81e10fd18c8d35b710ea1bfa938f4bf6f69f7ce60d770fb5101306fd85a6813e",
    ]
    # return all shares
    return xor_key_shares


@pytest.fixture
def key_share_reconstruct_xor_post_data(key_share_reconstruct_xor_key_shares):
    """
    Fixture to return key information data for Shamir Key Reconstruction.
    """
    return [{"key_share": share} for share in key_share_reconstruct_xor_key_shares]


@pytest.fixture
def key_share_shamir_secret_key():
    """
    Fixture to return shamir secret.
    """
    return "5b5239115089e0f9678ea6e49ef07b6a"


@pytest.fixture
def key_share_split_shamir_secret_key_post_data(key_share_shamir_secret_key):
    """
    Fixture to return xor secret key post data.
    """
    return {"key": key_share_shamir_secret_key}


@pytest.fixture
def key_share_xor_secret_key():
    """
    Fixture to return xor secret.
    """
    return "224bf03c918154989fb50bf145bae8d22afbcc0e352a0cea3cf66549d5cb6a47"


@pytest.fixture
def key_share_split_xor_secret_key_post_data(key_share_xor_secret_key):
    """
    Fixture to return xor secret key post data.
    """
    return {"key": key_share_xor_secret_key}


@pytest.fixture
def key_share_info_url():
    """
    Fixture to return the URL for the Key Share Info form.
    """
    return reverse("key-share-info")


@pytest.fixture
def key_share_reconstruct_url():
    """
    Fixture to return the URL for the Key share reconstruct form
    """
    return reverse("key-share-reconstruct")


@pytest.fixture
def key_share_split_url():
    """
    Fixture to return the URL for the Key share split form
    """
    return reverse("key-share-split")


@pytest.fixture
def key_share_result_url():
    """
    Fixture to return the URL for the Key share result page
    """
    return reverse("key-share-result")


@pytest.fixture
def key_share_info_html_page():
    """
    Fixture to return the Key Share Info HTML page.
    """
    return "cyph3r/key_share_templates/key-share-info.html"


@pytest.fixture
def key_share_reconstruct_html_page():
    """
    Fixture to return the key share reconstruct HTML page.
    """
    return "cyph3r/key_share_templates/key-share-reconstruct.html"


@pytest.fixture
def key_share_split_html_page():
    """
    Fixture to return the key share split HTML page.
    """
    return "cyph3r/key_share_templates/key-share-split.html"


@pytest.fixture
def key_share_download_html_page():
    """
    Fixture to return the key share download HTML page.
    """
    return "cyph3r/key_share_templates/key-share-download.html"


@pytest.fixture
def key_share_result_html_page():
    """
    Fixture to return the key share result HTML page.
    """
    return "cyph3r/key_share_templates/key-share-result.html"


##################
#  Data Protect  #
##################


@pytest.fixture
def data_protect_post_long_hex_string(pgp_public_keys):
    """
    Fixture to test app rejects invalid post data to data protect view.
    """
    return {
        "aead_mode": "gcm",
        "aead_operation": "encrypt",
        "aead_key": "12345cbfefee0a387b8443b1a859b36b1b71d8",
        "aad": "Hello",
        "plaintext": "cyph3r",
        "pgp_encrypt": True,
        "name": "test123",
        "public_key": pgp_public_keys["milenage_public_key"],
    }


@pytest.fixture
def data_protect_post_bad_hex_string(pgp_public_keys):
    """
    Fixture to test app rejects invalid post data to data protect view.
    """
    return {
        "aead_mode": "gcm",
        "aead_operation": "encrypt",
        "aead_key": "1YYZZ45cbfefee0a387b8443b1a859b36b1b71d8",
        "aad": "Hello",
        "plaintext": "cyph3r",
        "pgp_encrypt": True,
        "public_key": pgp_public_keys["milenage_public_key"],
        "name": "test123",
    }


@pytest.fixture
def data_protect_gcm_encrypt_post_data_pgp(pgp_public_keys):
    """
    Fixture to Post data for GCM encryption with PGP public keys.
    """
    return {
        "aead_mode": "gcm",
        "aead_operation": "encrypt",
        "aead_key": "5b5239115089e0f9678ea6e49ef07b6a",
        "aad": "Hello",
        "plaintext": "cyph3r",
        "pgp_encrypt": True,
        "name": "test123",
        "public_key": pgp_public_keys["milenage_public_key"],
    }


@pytest.fixture
def data_protect_chacha_encrypt_post_data_nopgp():
    """
    Fixture to Post data for Chacha encryption without PGP public keys.
    """
    return {
        "aead_mode": "chacha",
        "aead_operation": "encrypt",
        "aead_key": "8b7a760f18c47d98f6428416c37c50141e1614e2f78211e7e6cc027325456e28",
        "aad": "Hello",
        "plaintext": "cyph3r",
        "pgp_encrypt": False,
    }


@pytest.fixture
def data_protect_post_enable_pgp_encrypt_no_publickeys():
    """
    Fixture to test app returns errors when pgp_encrypt is enabled with no public keys uploaded.
    """
    return {
        "aead_mode": "gcm",
        "aead_operation": "encrypt",
        "aead_key": "bfefee0a387b8443b1a859b36b1b71d8",
        "aad": "Hello",
        "plaintext": "cyph3r",
        "pgp_encrypt": True,
    }


@pytest.fixture
def data_protect_post_128key_chacha_string():
    """
    Fixture to test app rejects Chacha keys that are not 256 bits.
    """
    return {
        "aead_mode": "chacha",
        "aead_operation": "encrypt",
        "aead_key": "bfefee0a387b8443b1a859b36b1b71d8",
        "aad": "Hello",
        "plaintext": "cyph3r",
        "pgp_encrypt": False,
    }


@pytest.fixture
def data_protect_url():
    """
    Fixture to return the URL for the Data Protect Info Form
    """
    return reverse("data-protect-info")


@pytest.fixture
def data_protect_info_html_page():
    """
    Fixture to return the Data Protect Info HTML page.
    """
    return "cyph3r/data_protect_templates/data-protect-info.html"


@pytest.fixture
def data_protect_download_html_page():
    """
    Fixture to return the Data Protect Download HTML page.
    """
    return "cyph3r/data_protect_templates/data-protect-download.html"


@pytest.fixture
def data_protect_result_html_page():
    """
    Fixture to return the Data Protect Result (no PGP upload) HTML page.
    """
    return "cyph3r/data_protect_templates/data-protect-result.html"


#######################
#  Wireless Fixtures  #
#######################


@pytest.fixture
def key_info_milenage_op_post_data():
    """
    Fixture to return key information data for Milenage OP key generation.
    """
    return {
        "key_identifier": "op_kid",
        "key_type": "op",
        "protocol": "milenage",
        "key_size": "128",
    }


@pytest.fixture
def key_info_milenage_transport_post_data():
    """
    Fixture to return key information data for Milenage OP key generation.
    """
    return {
        "key_identifier": "op_kid",
        "key_type": "transport",
        "protocol": "milenage",
        "key_size": "128",
    }


@pytest.fixture
def key_info_tuak_transport_post_data():
    """
    Fixture to return key information data for Tuak Transport key generation.
    """
    return {
        "key_identifier": "transport_kid",
        "key_type": "transport",
        "protocol": "tuak",
        "key_size": "256",
    }


@pytest.fixture
def key_info_tuak_op_post_data():
    """
    Fixture to return key information data for Tuak Transport key generation.
    """
    return {
        "key_identifier": "transport_kid",
        "key_type": "op",
        "protocol": "tuak",
        "key_size": "256",
    }


@pytest.fixture
def key_info_post_bad_data():
    """
    Fixture to check if validation errors are raised.
    """
    return {
        "key_identifier": "transport_kid",
        "key_type": "op",
        "protocol": "tuak",
        "key_size": "256",
    }


@pytest.fixture
def key_gcp_storage_post_data():
    """
    Fixture to return GCP information data for testing.
    """
    return {
        "gcp_project_id": "test-gcp-project-id",
        "gcp_kms_keyring": "",
        "gcp_kms_key": "",
    }


@pytest.fixture
def gcp_storage_url():
    """
    Fixture to return the URL for the GCP storage form.
    """
    return reverse("wireless_gcp_storage_form")


@pytest.fixture
def pgp_upload_url():
    """
    Fixture to return the URL for the PGP upload form.
    """
    return reverse("wireless-pgp-upload")


@pytest.fixture
def wireless_key_download_url():
    """
    Fixture to return the URL of page to dowload PGP encrypted Keys.
    """
    return reverse("wireless-key-download")


@pytest.fixture
def wireless_key_info_url():
    """
    Fixture to return the URL of page to Enter Wireless key information.
    """
    return reverse("wireless-key-info")


@pytest.fixture
def generate_keys_url():
    """
    Fixture to return the Generating key URL.
    """
    return reverse("wireless_generate_keys")


@pytest.fixture
def gcp_storage_html_page():
    """
    Fixture to return the HTML page for the GCP storage form.
    """
    return "cyph3r/wireless_templates/wireless-gcp-storage.html"


@pytest.fixture
def pgp_upload_html_page():
    """
    Fixture to return the HTML page for the PGP upload form.
    """
    return "cyph3r/wireless_templates/wireless-pgp-upload.html"


@pytest.fixture
def wireless_key_download_html_page():
    """
    Fixture to return the Generating key HTML page.
    """
    return "cyph3r/wireless_templates/wireless-key-download.html"


@pytest.fixture
def generate_keys_html_page():
    """
    Fixture to return the Generating key HTML page.
    """
    return "cyph3r/wireless_templates/wireless-generate-keys.html"
