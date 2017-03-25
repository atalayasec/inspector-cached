import pytest

test_urls = {
    "http://google.com" : True,
    "https://amazon.com" : True,
    "http://surelynottop.com" : False,
    "https://subdomain.google.com" : False,
    "http://google.surelynottop.com": False
}

@pytest.fixture(scope="session")
def validator():
    from top_validator import TopSite
    t = TopSite(autoload=False, debug=True)
    t._load_from_pickle()
    return t

@pytest.fixture(scope="module",
                params=test_urls.keys())
def task(request):
    from models import Task
    t = Task("url", url=request.param)
    return t

def test_validate(validator, task, capsys):
    with capsys.disabled():
        assert validator.validate(task) == test_urls[task.url]

