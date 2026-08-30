const bcrypt = require("bcrypt");

async function generateHash() {
    const adminHash = await bcrypt.hash("admin123", 10);
    const userHash = await bcrypt.hash("user123", 10);

    console.log("Admin Hash:", adminHash);
    console.log("User Hash :", userHash);
}

generateHash();