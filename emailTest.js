const nodemailer = require("nodemailer");

const EMAIL_USER = "kushhh2.0@gmail.com";     // example: abc@gmail.com
const EMAIL_PASS = "kushverma";        // NO SPACES

async function sendTestMail() {
  try {
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: EMAIL_USER,
        pass: EMAIL_PASS
      }
    });

    const info = await transporter.sendMail({
      from: EMAIL_USER,
      to: EMAIL_USER,
      subject: "✅ Email Test Successful",
      text: "If you received this email, Nodemailer is working perfectly."
    });

    console.log("✅ Email sent successfully:", info.response);
  } catch (err) {
    console.error("❌ Email error:", err.message);
  }
}

sendTestMail();
