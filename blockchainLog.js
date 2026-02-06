const crypto = require("crypto");
const fs = require("fs");

function calculateHash(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function addLog(entry) {
  let logs = [];

  if (fs.existsSync("logs.json")) {
    logs = JSON.parse(fs.readFileSync("logs.json"));
  }

  const previousHash = logs.length ? logs[logs.length - 1].hash : "GENESIS";

  const logData = {
    ...entry,
    previousHash,
    timestamp: new Date().toISOString()
  };

  logData.hash = calculateHash(JSON.stringify(logData));

  logs.push(logData);
  fs.writeFileSync("logs.json", JSON.stringify(logs, null, 2));
}

module.exports = addLog;
