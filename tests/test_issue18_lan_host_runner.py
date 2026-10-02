from pathlib import Path
import pytest
from test_issue18_lan_host_harness import harness


def test_existing_incomplete_evidence_directory_is_immutable(tmp_path):
    (tmp_path / 'progress.json').write_text('historical incomplete attempt')
    with pytest.raises(FileExistsError, match='fresh'):
        harness.run_acceptance(host='test', serial='test', output=tmp_path)
    assert (tmp_path / 'progress.json').read_text() == 'historical incomplete attempt'
