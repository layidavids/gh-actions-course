from django.db import models
from django.utils.timezone import now


class KeyGeneration(models.Model):
    """To keep track of generated keys"""

    key_id = models.CharField(max_length=255)  # identifier for the key
    date_generated = models.DateTimeField(auto_now_add=True)  # Timestamp of generation
    key_size = models.IntegerField()  # Key size in bits (e.g., 256, 4096)
    is_split = models.BooleanField(
        default=False
    )  # If the key was split after generation

    def __str__(self):
        return self.key_id


class KeySplit(models.Model):
    """To keep track of key splits"""

    class SplitType(models.TextChoices):
        XOR = "XOR", "xor"
        SHAMIR = "SHAMIR", "shamir"

    key = models.OneToOneField(
        KeyGeneration, on_delete=models.CASCADE, null=True
    )  # Reference to the generated key
    number_of_shares = models.IntegerField()  # Number of shares created
    type = models.CharField(
        max_length=10,
        choices=SplitType.choices,
    )  # Type of split

    def __str__(self):
        return f"Split of {self.key.key_id}"


class FileEncryption(models.Model):
    """To keep track of encrypted files"""

    key = models.ForeignKey(
        KeyGeneration, on_delete=models.CASCADE, null=True
    )  # Reference to the generated key
    encryption_algorithm = models.CharField(max_length=50)  # E.g., AES, RSA
    number_of_files_encrypted = models.IntegerField(
        default=0
    )  # Number of files encrypted

    def __str__(self):
        return self.file_id
