function makeDecision(context) {
  let decision = "ALLOW";
  let reason = "Access permitted";


  if (context.role !== "admin" && context.resource === "admin") {
    decision = "DENY";
    reason = "User role does not permit admin access";
  }

  
  if (context.role !== "admin") {
    if (context.time > 22 || context.time < 6) {
      decision = "DENY";
      reason = "Unusual access time detected";
    }
  }

  return { decision, reason };
}

module.exports = makeDecision;
