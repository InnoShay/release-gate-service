from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_valid_promote():
    payload = {
        "target": "preview",
        "event": "push",
        "ref": "refs/heads/main",
        "workflow": {
            "trigger": "push",
            "permissions": {"contents": "read", "packages": "write", "id-token": "none"},
            "testsPassed": True,
            "matrixComplete": True,
            "failFast": False,
            "actions": [
                {"owner": "actions", "name": "checkout", "ref": "v4"}
            ]
        },
        "image": {
            "multiStage": True,
            "runsAsRoot": False,
            "secretMode": "none",
            "criticalVulnerabilities": 0,
            "digestPinned": True
        }
    }
    response = client.post("/release-gate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "promote"
    assert data["violations"] == []

def test_violations():
    payload = {
        "target": "production",
        "event": "pull_request",
        "ref": "refs/heads/dev",
        "workflow": {
            "trigger": "pull_request_target",
            "permissions": {"contents": "write"},
            "testsPassed": False,
            "matrixComplete": False,
            "failFast": True,
            "actions": [
                {"owner": "thirdparty", "name": "action", "ref": "v1"}
            ]
        },
        "image": {
            "multiStage": False,
            "runsAsRoot": True,
            "secretMode": "arg",
            "criticalVulnerabilities": 5,
            "digestPinned": False
        }
    }
    response = client.post("/release-gate", json=payload)
    data = response.json()
    assert data["decision"] == "block"
    violations = set(data["violations"])
    expected = {
        "EXCESS_PERMISSION", "UNSAFE_PR_TRIGGER", "TESTS_INCOMPLETE",
        "MUTABLE_ACTION", "SINGLE_STAGE_IMAGE", "ROOT_RUNTIME",
        "SECRET_IN_LAYER", "CRITICAL_CVE", "UNPINNED_IMAGE",
        "INVALID_PRODUCTION_REF", "APPROVAL_REQUIRED"
    }
    assert violations == expected
