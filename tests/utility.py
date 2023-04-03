import sys
import random

from mock import patch, MagicMock, Mock


def mock_module(module_path):
    """Mock all modules given in path."""
    full_path = ""
    mocked_modules = []
    old_setup = {}
    for module_name in module_path.split("."):
        full_path += module_name
        mock_obj = None
        if sys.modules.get(full_path) and isinstance(sys.modules[full_path], MagicMock):
            mock_obj = sys.modules[full_path]
        else:
            old_setup[full_path] = sys.modules.get(full_path)
            mock_obj = sys.modules[full_path] = MagicMock(name="mock_" + module_name)
        mocked_modules.append(mock_obj)
        full_path += "."

    return mocked_modules, old_setup


def reset_mock_module(module_path, old_setup):
    """Reset mocked module."""
    full_path = ""
    mocked_modules = []
    for module_name in module_path.split("."):
        full_path += module_name
        if sys.modules.get(full_path) and isinstance(sys.modules[full_path], MagicMock):
            sys.modules[full_path] = old_setup.get(full_path)
        full_path += "."


def _mock_response(
    status=200,
    header={"Retry-After": 0.2, "Location": "test"},
    content="CONTENT",
    json_data=None,
    raise_for_status=None,
):
    """Return custom mock response."""
    mock_resp = Mock()
    # mock raise_for_status call w/optional error
    mock_resp.raise_for_status = Mock()
    if raise_for_status:
        mock_resp.raise_for_status.side_effect = raise_for_status
    # set status code and content
    mock_resp.status_code = status
    mock_resp.content = content
    mock_resp.headers = header
    # add json data if provided
    if json_data:
        mock_resp.json = Mock(return_value=json_data)
    return mock_resp


class SampleModularAction(object):
    """Sample class for Modular Action."""

    def __init__(self):
        """Init method."""
        super().__init__()
        self.session_key = "dummy_session"
        self.configuration = {"fqdn": "fqdn", "workload_uuid": "uuid"}

    def handle_response(*args, **kwargs):
        """Handle Response."""
        pass

    def dowork(*args, **kwargs):
        """Handle Response."""
        pass

    def message(*args, **kwargs):
        """Handle Response."""
        pass

    def setup_logger(*args, **kwargs):
        """Handle Response."""
        pass

    def addevent(self, message, sourcetype="sourcetype", status="status"):
        """AddEvent method."""
        print(message)
