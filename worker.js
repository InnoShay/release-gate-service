export default {
  async fetch(request, env, ctx) {
    if (request.method !== "POST" || new URL(request.url).pathname !== "/release-gate") {
      return new Response("Not found", { status: 404 });
    }

    try {
      const payload = await request.json();
      const violations = new Set();
      const workflow = payload.workflow || {};
      const image = payload.image || {};
      const event = payload.event;
      const target = payload.target;

      // 1. Permissions
      const perms = workflow.permissions || {};
      if (
        Object.keys(perms).length !== 3 ||
        perms["contents"] !== "read" ||
        perms["packages"] !== "write" ||
        perms["id-token"] !== "none"
      ) {
        violations.add("EXCESS_PERMISSION");
      }

      // 2. PR Trigger
      const trigger = workflow.trigger;
      if (event === "pull_request" && trigger !== "pull_request") {
        violations.add("UNSAFE_PR_TRIGGER");
      } else if (trigger === "pull_request_target") {
        violations.add("UNSAFE_PR_TRIGGER");
      }

      // 3. Tests
      if (!workflow.testsPassed || !workflow.matrixComplete || workflow.failFast !== false) {
        violations.add("TESTS_INCOMPLETE");
      }

      // 4. Actions
      const actions = workflow.actions || [];
      for (const action of actions) {
        if (action.owner !== "actions") {
          if (!/^[a-f0-9]{40}$/.test(action.ref || "")) {
            violations.add("MUTABLE_ACTION");
          }
        }
      }

      // 5. Image Checks
      if (!image.multiStage) violations.add("SINGLE_STAGE_IMAGE");
      if (image.runsAsRoot) violations.add("ROOT_RUNTIME");
      if (image.secretMode !== "none" && image.secretMode !== "buildkit") {
        violations.add("SECRET_IN_LAYER");
      }
      if ((image.criticalVulnerabilities || 0) > 0) violations.add("CRITICAL_CVE");
      if (!image.digestPinned) violations.add("UNPINNED_IMAGE");

      // 6. Production Checks
      if (target === "production") {
        if (event !== "push" || payload.ref !== "refs/heads/main") {
          violations.add("INVALID_PRODUCTION_REF");
        }
        if (!workflow.environmentApproval) {
          violations.add("APPROVAL_REQUIRED");
        }
      }

      const violationsList = Array.from(violations);
      const decision = violationsList.length > 0 ? "block" : "promote";

      return new Response(
        JSON.stringify({ decision, violations: violationsList }),
        { headers: { "content-type": "application/json" } }
      );
    } catch (e) {
      return new Response("Bad request", { status: 400 });
    }
  },
};
