require("dotenv").config();

const express = require("express");
const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
const twilio = require("twilio");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 3000;
const HOST = "0.0.0.0";

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

/* =====================================================
   USERS
===================================================== */

const users = require("./user");

/* =====================================================
   ENVIRONMENT CHECK
===================================================== */

const requiredEnv = [
  "JWT_SECRET",
  "TWILIO_SID",
  "TWILIO_TOKEN",
  "TWILIO_PHONE_NUMBER",
  "ALERT_PHONE_NUMBER",
  "EMAIL_USER",
  "EMAIL_PASS"
];

for (const key of requiredEnv) {
  if (!process.env[key]) {
    console.warn(`⚠️ Missing environment variable: ${key}`);
  }
}

/* =====================================================
   TWILIO
===================================================== */

const twilioClient = twilio(
  process.env.TWILIO_SID,
  process.env.TWILIO_TOKEN
);

/* =====================================================
   EMAIL
===================================================== */

const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASS = process.env.EMAIL_PASS;

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: EMAIL_USER,
    pass: EMAIL_PASS
  }
});

/* =====================================================
   SECURITY STATE
===================================================== */

const failedAttempts = {};
const userActivity = {};
const lockedAccounts = {};
const pendingOTPs = {};

/*
pendingOTPs[username] = {
  otpHash,
  expiresAt,
  attempts,
  ip,
  userAgent
}
*/

/* =====================================================
   LOG FILE
===================================================== */

const LOG_FILE = path.join(__dirname, "logs.json");

/* =====================================================
   SAFE LOGGING
===================================================== */

function logDecision(log) {
  let logs = [];

  try {
    if (fs.existsSync(LOG_FILE)) {
      const data = fs.readFileSync(LOG_FILE, "utf8");

      if (data.trim()) {
        logs = JSON.parse(data);

        if (!Array.isArray(logs)) {
          logs = [];
        }
      }
    }
  } catch (error) {
    console.error("❌ Log read error:", error.message);
    logs = [];
  }

  logs.push(log);

  /*
    Keep the log file from growing forever.
    The latest 5000 events are retained.
  */
  if (logs.length > 5000) {
    logs = logs.slice(-5000);
  }

  try {
    fs.writeFileSync(
      LOG_FILE,
      JSON.stringify(logs, null, 2),
      "utf8"
    );
  } catch (error) {
    console.error("❌ Log write error:", error.message);
  }
}

/* =====================================================
   EMAIL ALERT
===================================================== */

async function sendEmailAlert(message) {
  try {
    await transporter.sendMail({
      from: EMAIL_USER,
      to: EMAIL_USER,
      subject: "🚨 NEXORA SECURITY ALERT",
      text: message
    });

    console.log("📧 Email security alert sent.");
    return true;

  } catch (error) {
    console.error(
      "❌ Email alert failed:",
      error.message
    );

    return false;
  }
}

/* =====================================================
   SMS SECURITY ALERT
===================================================== */

async function sendSecurityAlertSMS({
  username,
  ip,
  riskScore,
  attackType,
  failedAttempts,
  eventType = "Security Event"
}) {
  try {
    const message = `🚨 NEXORA SECURITY ALERT

Event: ${eventType}
Account: ${username}
IP Address: ${ip}
Risk Score: ${riskScore}/100
Attack: ${attackType}
Failed Attempts: ${failedAttempts}

Time: ${new Date().toLocaleString()}`;

    await twilioClient.messages.create({
      body: message,
      from: process.env.TWILIO_PHONE_NUMBER,
      to: process.env.ALERT_PHONE_NUMBER
    });

    console.log(
      "📱 SMS security alert sent successfully."
    );

    return true;

  } catch (error) {

    console.error(
      "❌ SMS failed:",
      error.message
    );

    return false;
  }
}

/* =====================================================
   OTP EMAIL
===================================================== */

async function sendOTPEmail(username, otp) {

  try {

    await transporter.sendMail({

      from: EMAIL_USER,

      to: EMAIL_USER,

      subject:
        "🔐 Nexora Security - Login Verification Code",

      text: `NEXORA SECURITY

Hello ${username},

Your login verification code is:

${otp}

This code will expire in 5 minutes.

If you did not attempt to log in, please secure your account immediately.

Nexora Security Command Center`
    });

    console.log("📧 OTP sent successfully.");

    return true;

  } catch (error) {

    console.error(
      "❌ OTP email failed:",
      error.message
    );

    return false;
  }
}

/* =====================================================
   RISK CALCULATION
===================================================== */

function calculateRisk(ip, userAgent) {

  let score = 0;

  /*
    Failed attempts from this IP
  */
  score +=
    (failedAttempts[ip] || 0) * 15;

  /*
    Non-browser clients receive a small risk increase.
  */
  const browserDetected =
    /Chrome|Firefox|Safari|Edg/i.test(
      userAgent
    );

  if (!browserDetected) {
    score += 20;
  }

  /*
    Unusual access time
  */
  const hour =
    new Date().getHours();

  if (hour < 6 || hour >= 23) {
    score += 25;
  }

  return Math.min(
    Math.max(score, 0),
    100
  );
}

/* =====================================================
   ATTACK DETECTION
===================================================== */

function detectAttack(
  ip,
  username,
  risk,
  userAgent
) {

  if (
    /Postman|Thunder Client|Insomnia/i.test(
      userAgent
    )
  ) {
    return "Automated Client";
  }

  if (
    username === "admin" &&
    (failedAttempts[ip] || 0) >= 2
  ) {
    return "Credential Stuffing";
  }

  if (
    (failedAttempts[ip] || 0) >= 4
  ) {
    return "Brute Force Attack";
  }

  if (risk >= 60) {
    return "Suspicious Login";
  }

  const hour =
    new Date().getHours();

  if (hour < 6 || hour >= 23) {
    return "Unusual Time Access";
  }

  return "Normal";
}

/* =====================================================
   JWT VERIFICATION
===================================================== */

function verifyToken(req, res, next) {

  const authHeader =
    req.headers.authorization;

  if (!authHeader) {

    return res.status(401).json({
      message: "Authentication required"
    });
  }

  if (!authHeader.startsWith("Bearer ")) {

    return res.status(401).json({
      message: "Invalid authorization format"
    });
  }

  const token =
    authHeader.substring(7);

  try {

    const decoded =
      jwt.verify(
        token,
        process.env.JWT_SECRET
      );

    req.user = decoded;

    next();

  } catch (error) {

    return res.status(403).json({
      message: "Invalid or expired token"
    });
  }
}

/* =====================================================
   LOGIN
===================================================== */

app.post("/login", async (req, res) => {

  try {

    const username =
      String(req.body.username || "").trim();

    const password =
      String(req.body.password || "");

    const ip =
      req.ip ||
      req.socket.remoteAddress ||
      "Unknown";

    const userAgent =
      req.headers["user-agent"] || "Unknown";

    /*
      Basic validation
    */

    if (!username || !password) {

      return res.status(400).json({
        message:
          "Username and password are required"
      });
    }

    /*
      Initialize counters
    */

    if (!failedAttempts[ip]) {
      failedAttempts[ip] = 0;
    }

    if (!failedAttempts[username]) {
      failedAttempts[username] = 0;
    }

    /* =================================================
       ACCOUNT LOCK CHECK
    ================================================= */

    if (lockedAccounts[username]) {

      const lockTime =
        lockedAccounts[username];

      if (Date.now() < lockTime) {

        const remainingMinutes =
          Math.ceil(
            (lockTime - Date.now()) /
            60000
          );

        console.log(
          "🔒 LOGIN BLOCKED:",
          username
        );

        return res.status(403).json({

          message:
            "Account is temporarily locked",

          remainingMinutes

        });
      }

      /*
        Lock expired
      */

      delete lockedAccounts[username];

      failedAttempts[username] = 0;

      console.log(
        "🔓 Account lock expired:",
        username
      );
    }

    /* =================================================
       FIND USER
    ================================================= */

    const user =
      users.find(
        u => u.username === username
      );

    /*
      Always perform password comparison
      when possible to reduce obvious
      username enumeration differences.
    */

    let passwordMatch = false;

    if (user) {

      passwordMatch =
        await bcrypt.compare(
          password,
          user.password
        );

    }

    /* =================================================
       FAILED LOGIN
    ================================================= */

    if (!user || !passwordMatch) {

      failedAttempts[ip]++;
      failedAttempts[username]++;

      const risk =
        calculateRisk(
          ip,
          userAgent
        );

      const attackType =
        detectAttack(
          ip,
          username,
          risk,
          userAgent
        );

      console.log("--------------------------------");
      console.log("❌ FAILED LOGIN");
      console.log("User:", username);
      console.log("IP:", ip);
      console.log(
        "Attempts:",
        failedAttempts[username]
      );
      console.log("Risk:", risk);
      console.log("Attack:", attackType);
      console.log("--------------------------------");

      /* =================================================
         LOCK AFTER 5 FAILED ATTEMPTS
      ================================================= */

      if (
        failedAttempts[username] >= 5
      ) {

        lockedAccounts[username] =
          Date.now() +
          10 * 60 * 1000;

        const alertMessage = `🚨 CRITICAL SECURITY ALERT

ACCOUNT LOCKED

User: ${username}
IP: ${ip}
Failed Attempts: ${failedAttempts[username]}
Risk: 100
Attack: Brute Force Attack
Lock Duration: 10 minutes
Time: ${new Date().toLocaleString()}
`;

        console.log(alertMessage);

        /*
          Send notifications.
        */

        await sendEmailAlert(
          alertMessage
        );

        await sendSecurityAlertSMS({

          username,

          ip,

          riskScore: 100,

          attackType:
            "Brute Force Attack",

          failedAttempts:
            failedAttempts[username],

          eventType:
            "ACCOUNT LOCKED"

        });

        /*
          Store event
        */

        logDecision({

          username,

          decision:
            "LOCKED",

          risk: 100,

          attackType:
            "Brute Force Attack",

          attempts:
            failedAttempts[username],

          ip,

          userAgent,

          time:
            new Date().toISOString()

        });

        return res.status(403).json({

          message:
            "Account locked after 5 failed attempts",

          lockDuration:
            "10 minutes"

        });
      }

      /* =================================================
         NORMAL FAILED LOGIN
      ================================================= */

      const alertMessage = `🚨 SECURITY EVENT

User: ${username}
IP: ${ip}
Risk: ${risk}
Attack: ${attackType}
Failed Attempts: ${failedAttempts[ip]}
Time: ${new Date().toLocaleString()}
`;

      console.log(alertMessage);

      /*
        Email notification
      */

      await sendEmailAlert(
        alertMessage
      );

      /*
        Log event
      */

      logDecision({

        username,

        decision:
          "DENY",

        risk,

        attackType,

        attempts:
          failedAttempts[ip],

        ip,

        userAgent,

        time:
          new Date().toISOString()

      });

      return res.status(401).json({

        message:
          "Invalid credentials",

        risk,

        attackType

      });
    }

    /* =================================================
       PASSWORD CORRECT
       REQUIRE 2FA
    ================================================= */

    failedAttempts[ip] = 0;

    console.log("--------------------------------");
    console.log("✅ PASSWORD VERIFIED");
    console.log("User:", username);
    console.log("🔐 2FA REQUIRED");
    console.log("--------------------------------");

    /*
      Generate 6 digit OTP
    */

    const otp =
      crypto
        .randomInt(
          100000,
          1000000
        )
        .toString();

    /*
      Hash OTP
    */

    const otpHash =
      await bcrypt.hash(
        otp,
        10
      );

    /*
      Store OTP
    */

    pendingOTPs[username] = {

      otpHash,

      expiresAt:
        Date.now() +
        5 * 60 * 1000,

      attempts: 0,

      ip,

      userAgent

    };

    /*
      Send OTP
    */

    const otpSent =
      await sendOTPEmail(
        username,
        otp
      );

    if (!otpSent) {

      delete pendingOTPs[username];

      return res.status(500).json({

        message:
          "Unable to send verification code"

      });
    }

    /*
      Log 2FA request
    */

    logDecision({

      username,

      decision:
        "2FA_REQUIRED",

      risk: 0,

      attackType:
        "None",

      attempts: 0,

      ip,

      userAgent,

      time:
        new Date().toISOString()

    });

    /*
      DO NOT CREATE JWT YET.
    */

    return res.json({

      message:
        "Password verified. OTP required.",

      requiresOTP:
        true,

      username

    });

  } catch (error) {

    console.error(
      "❌ Login error:",
      error
    );

    return res.status(500).json({

      message:
        "Internal server error"

    });
  }
});

/* =====================================================
   VERIFY OTP
===================================================== */

app.post(
  "/verify-otp",
  async (req, res) => {

    try {

      const username =
        String(
          req.body.username || ""
        ).trim();

      const otp =
        String(
          req.body.otp || ""
        ).trim();

      if (!username || !otp) {

        return res.status(400).json({

          message:
            "Username and OTP are required"

        });
      }

      const pending =
        pendingOTPs[username];

      /* =================================================
         NO OTP
      ================================================= */

      if (!pending) {

        return res.status(400).json({

          message:
            "No active OTP request. Please login again."

        });
      }

      /* =================================================
         EXPIRATION
      ================================================= */

      if (
        Date.now() >
        pending.expiresAt
      ) {

        delete pendingOTPs[username];

        return res.status(401).json({

          message:
            "OTP expired. Please login again."

        });
      }

      /* =================================================
         MAX OTP ATTEMPTS
      ================================================= */

      if (
        pending.attempts >= 3
      ) {

        delete pendingOTPs[username];

        logDecision({

          username,

          decision:
            "2FA_BLOCKED",

          risk: 80,

          attackType:
            "OTP Brute Force",

          attempts: 3,

          ip:
            pending.ip,

          userAgent:
            pending.userAgent,

          time:
            new Date().toISOString()

        });

        return res.status(403).json({

          message:
            "Too many incorrect OTP attempts. Login again."

        });
      }

      /* =================================================
         VERIFY OTP
      ================================================= */

      const validOTP =
        await bcrypt.compare(
          otp,
          pending.otpHash
        );

      if (!validOTP) {

        pending.attempts++;

        console.log(
          "❌ Invalid OTP:",
          username,
          "Attempt:",
          pending.attempts
        );

        logDecision({

          username,

          decision:
            "2FA_DENY",

          risk: 70,

          attackType:
            "Invalid OTP",

          attempts:
            pending.attempts,

          ip:
            pending.ip,

          userAgent:
            pending.userAgent,

          time:
            new Date().toISOString()

        });

        return res.status(401).json({

          message:
            "Invalid verification code",

          remainingAttempts:
            3 - pending.attempts

        });
      }

      /* =================================================
         OTP SUCCESS
      ================================================= */

      const originalIP =
        pending.ip;

      const originalUserAgent =
        pending.userAgent;

      delete pendingOTPs[username];

      const user =
        users.find(
          u => u.username === username
        );

      if (!user) {

        return res.status(401).json({

          message:
            "User not found"

        });
      }

      /* =================================================
         CREATE JWT
      ================================================= */

      const token =
        jwt.sign(

          {

            username:
              user.username,

            role:
              user.role

          },

          process.env.JWT_SECRET,

          {

            expiresIn:
              "1h"

          }
        );

      console.log("--------------------------------");
      console.log("🔐 2FA SUCCESS");
      console.log("✅ LOGIN SUCCESSFUL");
      console.log("User:", username);
      console.log("--------------------------------");

      /* =================================================
         LOG SUCCESS
      ================================================= */

      logDecision({

        username,

        decision:
          "ALLOW",

        risk: 0,

        attackType:
          "None",

        attempts: 0,

        ip:
          originalIP,

        userAgent:
          originalUserAgent,

        time:
          new Date().toISOString()

      });

      return res.json({

        message:
          "Login successful",

        token,

        username,

        risk: 0,

        attackType:
          "None"

      });

    } catch (error) {

      console.error(
        "❌ OTP verification error:",
        error
      );

      return res.status(500).json({

        message:
          "Internal server error"

      });
    }
  }
);

/* =====================================================
   SECURE DATA
===================================================== */

app.get(
  "/secure-data",
  verifyToken,
  (req, res) => {

    const username =
      req.user.username;

    const ip =
      req.ip;

    if (!userActivity[ip]) {
      userActivity[ip] = 0;
    }

    userActivity[ip]++;

    /*
      Simple activity threshold
    */

    if (
      userActivity[ip] > 5
    ) {

      logDecision({

        username,

        decision:
          "BLOCKED",

        risk: 90,

        attackType:
          "Excessive Request Activity",

        attempts:
          userActivity[ip],

        ip,

        time:
          new Date().toISOString()

      });

      return res.status(429).send(`

<!DOCTYPE html>

<html>

<head>

<title>Security Alert</title>

</head>

<body style="
background:#050607;
color:#ff5d6c;
text-align:center;
padding-top:100px;
font-family:Arial;
">

<h1>
🚨 Security Protection Triggered
</h1>

<h2>
User: ${escapeHTML(username)}
</h2>

<h2>
IP: ${escapeHTML(ip)}
</h2>

<p>
Excessive request activity detected.
</p>

</body>

</html>

      `);
    }

    return res.send(`

<!DOCTYPE html>

<html>

<head>

<title>Secure Data</title>

</head>

<body style="
background:#050607;
color:white;
text-align:center;
padding-top:100px;
font-family:Arial;
">

<div style="
background:#11151c;
padding:30px;
border-radius:12px;
display:inline-block;
border:1px solid #293343;
">

<h1>
🔓 Secure Data Accessed
</h1>

<h2>
Welcome ${escapeHTML(username)}
</h2>

<p>
Protected resource access granted.
</p>

</div>

</body>

</html>

    `);
  }
);

/* =====================================================
   ADMIN PANEL
===================================================== */

app.get(
  "/admin-panel",
  verifyToken,
  (req, res) => {

    const username =
      req.user.username;

    const ip =
      req.ip;

    /*
      Authorization check
    */

    if (
      req.user.role !== "admin"
    ) {

      logDecision({

        username,

        decision:
          "DENY",

        risk: 90,

        attackType:
          "Privilege Escalation",

        attempts: 1,

        ip,

        time:
          new Date().toISOString()

      });

      return res.status(403).send(`

<!DOCTYPE html>

<html>

<head>

<title>Unauthorized</title>

</head>

<body style="
background:#050607;
color:#ff5d6c;
text-align:center;
padding-top:100px;
font-family:Arial;
">

<div style="
background:#1a0b0e;
padding:30px;
border-radius:12px;
display:inline-block;
border:1px solid #542027;
">

<h1>
🚨 Unauthorized Access
</h1>

<h2>
Attack: Privilege Escalation
</h2>

<h3>
User: ${escapeHTML(username)}
</h3>

</div>

</body>

</html>

      `);
    }

    return res.send(`

<!DOCTYPE html>

<html>

<head>

<title>Admin Panel</title>

</head>

<body style="
background:#050607;
color:white;
text-align:center;
padding-top:100px;
font-family:Arial;
">

<div style="
background:#11151c;
padding:30px;
border-radius:12px;
display:inline-block;
border:1px solid #293343;
">

<h1>
👑 Welcome Admin
</h1>

<h2>
Full Access Granted
</h2>

<p>
Administrative authorization verified.
</p>

</div>

</body>

</html>

    `);
  }
);

/* =====================================================
   SECURITY LOGS
===================================================== */

app.get(
  "/logs",
  verifyToken,
  (req, res) => {

    if (
      !fs.existsSync(LOG_FILE)
    ) {

      return res.json([]);

    }

    try {

      const data =
        fs.readFileSync(
          LOG_FILE,
          "utf8"
        );

      if (!data.trim()) {

        return res.json([]);

      }

      const logs =
        JSON.parse(data);

      if (!Array.isArray(logs)) {

        return res.json([]);

      }

      return res.json(logs);

    } catch (error) {

      console.error(
        "❌ Log read error:",
        error.message
      );

      return res.status(500).json({

        message:
          "Unable to read security logs"

      });
    }
  }
);

/* =====================================================
   SECURITY STATUS API
===================================================== */

app.get(
  "/security-status",
  verifyToken,
  (req, res) => {

    const activeLocks =
      Object.keys(
        lockedAccounts
      ).length;

    const pending2FA =
      Object.keys(
        pendingOTPs
      ).length;

    return res.json({

      status:
        "operational",

      monitoring:
        true,

      activeLocks,

      pending2FA,

      timestamp:
        new Date().toISOString()

    });
  }
);

/* =====================================================
   HEALTH CHECK
===================================================== */

app.get(
  "/health",
  (req, res) => {

    res.json({

      status:
        "online",

      service:
        "Nexora Security",

      time:
        new Date().toISOString()

    });
  }
);

/* =====================================================
   HTML ESCAPE
===================================================== */

function escapeHTML(value) {

  if (
    value === null ||
    value === undefined
  ) {

    return "";

  }

  return String(value)

    .replace(
      /&/g,
      "&amp;"
    )

    .replace(
      /</g,
      "&lt;"
    )

    .replace(
      />/g,
      "&gt;"
    )

    .replace(
      /"/g,
      "&quot;"
    )

    .replace(
      /'/g,
      "&#039;"
    );
}

/* =====================================================
   CLEAN EXPIRED OTPs
===================================================== */

setInterval(() => {

  const now =
    Date.now();

  for (
    const username
    of Object.keys(pendingOTPs)
  ) {

    if (
      pendingOTPs[username].expiresAt <
      now
    ) {

      delete pendingOTPs[username];

      console.log(
        "🧹 Expired OTP removed:",
        username
      );
    }
  }

}, 60 * 1000);

/* =====================================================
   SERVER
===================================================== */

app.listen(
  PORT,
  HOST,
  () => {

    console.log("");
    console.log("========================================");
    console.log("🚀 NEXORA SECURITY COMMAND CENTER");
    console.log("========================================");
    console.log(
      `🌐 http://localhost:${PORT}`
    );
    console.log(
      `📡 Network: http://YOUR-PC-IP:${PORT}`
    );
    console.log("🛡️ Authentication monitoring: ACTIVE");
    console.log("🔐 Two-factor authentication: ACTIVE");
    console.log("📱 SMS alerts: ENABLED");
    console.log("📧 Email alerts: ENABLED");
    console.log("📊 Security logging: ENABLED");
    console.log("========================================");
    console.log("");

  }
);