from guardcli.utils.validator import validate_url
from guardcli.exceptions import InvalidTargetError
import pytest

def test_validate_url_valid():
    assert validate_url("example.com") == "https://example.com"
    assert validate_url("http://example.com") == "http://example.com"

def test_validate_url_invalid():
    with pytest.raises(InvalidTargetError):
        validate_url("http://")
