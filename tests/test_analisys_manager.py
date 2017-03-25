import pytest

import analysis_manager as am

class TestAnalysisManager(object):
    def test_get_manager(self):
        with pytest.raises(ValueError):
            am.get_manager()

