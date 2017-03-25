import pytest

from base_analyser import BaseAnalyser

def test_empty_create():
    with pytest.raises(ValueError):
        b = BaseAnalyser()

