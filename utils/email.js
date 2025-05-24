const nodemailer = require('nodemailer');
require('dotenv').config();

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,     // e.g., your_email@gmail.com
    pass: process.env.EMAIL_PASS      // App password from Google
  }
});

// ✅ 1. Send QR Code Ticket Email
async function sendTicketEmail(to, qrBuffer) {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to,
    subject: 'Your Event Ticket (QR Code)',
    html: `
      <h2>🎟️ Your Event Ticket</h2>
      <p>This ticket is valid for one entry only. Please present the QR code below at the event gate.</p>
      <img src="cid:qr@ticket" alt="QR Code" />
    `,
    attachments: [{
      filename: 'ticket.png',
      content: qrBuffer,
      cid: 'qr@ticket'
    }]
  };

  return transporter.sendMail(mailOptions);
}

// ✅ 2. Send OTP Email
async function sendOtpEmail(to, otp) {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to,
    subject: 'Your OTP Code for Event Booking',
    html: `
      <h3>🔐 Your One-Time Password</h3>
      <p>Your OTP is: <strong>${otp}</strong></p>
      <p>This code will expire in 5 minutes and can be used once.</p>
    `
  };

  return transporter.sendMail(mailOptions);
}

module.exports = {
  sendTicketEmail,
  sendOtpEmail
};
