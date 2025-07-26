from cyph3r.models import KeySplit, FileEncryption

""" Helper functions to track key shares and encrypted files """


def total_key_shares():
    """Returns the total number of key shares created"""
    return sum([k.number_of_shares for k in KeySplit.objects.all()])


def total_files_encrypted():
    """Returns the total number of files encrypted"""
    return sum([f.number_of_files_encrypted for f in FileEncryption.objects.all()])
