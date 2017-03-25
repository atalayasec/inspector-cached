import pytest

test_urls = {
    "http://example.com" : ValueError,
    "https://amazon.com" : True,
    "https://expired.badssl.com/" : False,
    "https://self-signed.badssl.com/" : False,
    "https://untrusted-root.badssl.com/": False
}

@pytest.fixture(scope="session")
def validator():
    from ssl_validator import SSLSite
    s = SSLSite(debug=True)
    return s

@pytest.fixture(scope="module",
                params=test_urls.keys())
def task(request):
    from models import Task
    t = Task("url", url=request.param)
    return t

def test_validate(validator, task, capsys):
    result = test_urls[task.url]
    if isinstance(result, bool):
        assert validator.validate(task) == result
    else:
        with pytest.raises(result):
            validator.validate(task)

