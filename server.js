const express = require("express");
const bodyParser = require("body-parser");
const fs = require("fs");
const nodemailer = require("nodemailer");

const users = require("./users");
const makeDecision = require("./decisionEngine");
const logDecision = require("./logger");

const app = express();
app.use(bodyParser.json());
app.use(express.static("public"));

const EMAIL_USER = "kushhh2.0@gmail.com";     // 👈 PUT YOUR GMAIL HERE
const EMAIL_PASS = "kushverma";        // 👈 PUT APP PASSWORD HERE

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: EMAIL_USER,
    pass: EMAIL_PASS
  }
});

function sendEmailAlert(username, ip) {
  const mailOptions = {
    from: EMAIL_USER,
    to: EMAIL_USER, // you will receive alert on same email
    subject: "🚨 Security Alert: Invalid Login Attempt",
    html: `
      <h2 style="color:red;">Security Alert</h2>
      <p><b>Invalid login attempt detected</b></p>
      <p><b>User:</b> ${username}</p>
      <p><b>IP Address:</b> ${ip}</p>
      <p><b>Time:</b> ${new Date().toLocaleString()}</p>
    `
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.log("❌ Email error:", error);
    } else {
      console.log("📧 Security alert email sent");
    }
  });
}

/* ===========================
   🚫 LOGIN ATTEMPT TRACKING
   =========================== */

let failedAttempts = {};
const MAX_ATTEMPTS = 4;

app.post("/login", (req, res) => {
  const { username, password, resource } = req.body;
  const ip = req.ip;

  if (!failedAttempts[ip]) failedAttempts[ip] = 0;

  if (failedAttempts[ip] >= MAX_ATTEMPTS) {
    return res.status(403).json({
      message: "Too many failed attempts. Refresh server to try again."
    });
  }

  const user = users.find(
    u => u.username === username && u.password === password
  );

  if (!user) {
    failedAttempts[ip]++;

    // 📧 SEND EMAIL ON INVALID LOGIN
    sendEmailAlert(username || "Unknown", ip);

    return res.status(401).json({
      message: "Invalid credentials"
    });
  }

  // reset attempts on success
  failedAttempts[ip] = 0;

  const context = {
    role: user.role,
    resource,
    ip,
    device: req.headers["user-agent"],
    time: new Date().getHours()
  };

  const { decision, reason } = makeDecision(context);
  logDecision(username, decision, reason, context);

  res.json({
    decision,
    justification: reason
  });
});

app.get("/logs", (req, res) => {
  if (!fs.existsSync("logs.json")) {
    return res.json([]);
  }
  const data = fs.readFileSync("logs.json", "utf-8");
  res.json(JSON.parse(data));
});

app.listen(3000, () => {
  console.log("✅ Server running on http://localhost:3000");
});
