import os
import pytest


@pytest.fixture(autouse=True, scope='session')
def ensure_cert_master_key():
    """Asegura que `CERT_MASTER_KEY` esté presente en el entorno para tests."""
    os.environ.setdefault('CERT_MASTER_KEY', 'test-master-key')
    # Skip signing in tests by default to speed up suite and avoid external cert ops
    os.environ.setdefault('DTE_TEST_NO_SIGN', '1')
    yield
