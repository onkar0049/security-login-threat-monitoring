const crypto = require("crypto");
const fs = require("fs");


function calculateHash(data) {
  return crypto
    .createHash("sha256")
    .update(data)
    .digest("hex");
}


function addLog(entry) {

  let logs = [];


  if (fs.existsSync("logs.json")) {

    const data = fs.readFileSync("logs.json");

    if (data.length) {
      logs = JSON.parse(data);
    }
  }

  
  const previousHash =
    logs.length > 0
      ? logs[logs.length - 1].hash
      : "GENESIS";

  
  const hash = calculateHash(
    JSON.stringify(entry) + previousHash
  );

  const blockchainEntry = {
    ...entry,
    previousHash,
    hash
  };

  // Add log
  logs.push(blockchainEntry);

  // Save logs
  fs.writeFileSync(
    "logs.json",
    JSON.stringify(logs, null, 2)
  );

  console.log("✅ Blockchain log added");
}

module.exports = addLog;