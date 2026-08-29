from fastapi import FastAPI, Request
import re

app = FastAPI()
#app.route
@app.post("/release-gate")
async def release_gate(request: Request):
    payload = await request.json()
    violations = set()

    workflow = payload.get("workflow", {})
    image = payload.get("image", {})
    
    # 1. Permissions must be exactly least privilege for a release
    permissions = workflow.get("permissions", {})
    expected_permissions = {"contents": "read", "packages": "write", "id-token": "none"}
    if permissions != expected_permissions:
        violations.add("EXCESS_PERMISSION")
    
    # 2. A pull request must use pull_request, never pull_request_target.
    event = payload.get("event")
    trigger = workflow.get("trigger")
    if event == "pull_request" and trigger != "pull_request":
        violations.add("UNSAFE_PR_TRIGGER")
    elif trigger == "pull_request_target":
        violations.add("UNSAFE_PR_TRIGGER")

    # 3. Tests must pass, the whole matrix must finish, and failFast must be false.
    if not workflow.get("testsPassed") or not workflow.get("matrixComplete") or workflow.get("failFast") is not False:
        violations.add("TESTS_INCOMPLETE")

    # 4. Actions owned by actions may use a version tag. Every third-party action must be pinned to a full 40-character lowercase hex SHA.
    for action in workflow.get("actions", []):
        owner = action.get("owner")
        ref = action.get("ref", "")
        if owner != "actions":
            if not re.match(r'^[a-f0-9]{40}$', ref):
                violations.add("MUTABLE_ACTION")

    # 5. Image checks
    if not image.get("multiStage"):
        violations.add("SINGLE_STAGE_IMAGE")
    
    if image.get("runsAsRoot"):
        violations.add("ROOT_RUNTIME")
        
    if image.get("secretMode") not in ["none", "buildkit"]:
        violations.add("SECRET_IN_LAYER")
        
    if image.get("criticalVulnerabilities", 0) > 0:
        violations.add("CRITICAL_CVE")
        
    if not image.get("digestPinned"):
        violations.add("UNPINNED_IMAGE")

    # 6. Production additionally requires a push on refs/heads/main and an environmentApproval: true
    target = payload.get("target")
    if target == "production":
        if event != "push" or payload.get("ref") != "refs/heads/main":
            violations.add("INVALID_PRODUCTION_REF")
        if not workflow.get("environmentApproval"):
            violations.add("APPROVAL_REQUIRED")

    violations_list = list(violations)
    return {
        "decision": "block" if violations_list else "promote",
        "violations": violations_list
    }
