const addLog = require("./blockchainLog");

function logDecision(user, decision, reason, context) {
  addLog({
    user,
    decision,
    justification: reason,
    context
  });
}

module.exports = logDecision;
