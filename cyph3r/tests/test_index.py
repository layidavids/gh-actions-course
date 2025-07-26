import pytest
from django.urls import reverse


@pytest.mark.django_db
def test_index_view(client):
    """
    Test that the index view renders correctly.
    """
    url = reverse("index")  # Get the URL for the index view
    response = client.get(url)
    assert response.status_code == 200
    assert "cyph3r/index.html" in [t.name for t in response.templates]
