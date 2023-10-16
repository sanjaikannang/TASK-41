const bodyParser = require("body-parser");
const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const bcrypt = require("bcrypt");
const crypto = require('crypto'); 
const nodemailer = require("nodemailer"); // Add nodemailer for email sending

require("dotenv").config();

const app = express();

app.use(cors());

app.use(bodyParser.json());

const PORT = process.env.PORT;
const DB_URL = process.env.DB_URL;

// Connect to MongoDB
mongoose
  .connect(DB_URL, {})
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.log("Could not connect to MongoDB", err));

// Define the User schema
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    resetToken: String,
    resetTokenExpiration: Date,
});
const User = mongoose.model('User', userSchema);

// Route to generate a random token, store it in the database, and send a reset link
app.post('/generate-reset-token', async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Generate a random token
    const resetToken = crypto.randomBytes(20).toString('hex');

    // Store the token in the database and set an expiration time (e.g., 1 hour)
    user.resetToken = resetToken;
    user.resetTokenExpiration = Date.now() + 3600000; // 1 hour

    await user.save();

    // Send a password reset email with the reset link
    const resetLink = `${resetToken}`;
    
    // Configure nodemailer to send the email
    const transporter = nodemailer.createTransport({
      service: 'Gmail',
      auth: {
        user: process.env.EMAIL_USERNAME, // Your email username
        pass: process.env.EMAIL_PASSWORD, // Your email password
      },
    });

    const mailOptions = {
        from: process.env.EMAIL_USERNAME, // Your email
        to: email, // User's email
        subject: 'Password Reset',
        html: `<p>Your token to reset the password: ${resetToken}</p>`,
      };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        return res.status(500).json({ error: 'Email could not be sent' });
      }
      res.json({ message: 'Password reset link sent' });
    });
  } catch (error) {
    res.status(500).json({ error: 'Password reset failed' });
  }
});

// Route to verify the token and reset the password
app.post('/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;

  try {
    const user = await User.findOne({
      resetToken: token,
      resetTokenExpiration: { $gt: Date.now() }, // Check if token is not expired
    });

    if (!user) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }

    // Reset the password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.resetToken = undefined;
    user.resetTokenExpiration = undefined;

    await user.save();

    res.json({ message: 'Password reset successful' });
  } catch (error) {
    res.status(500).json({ error: 'Password reset failed' });
  }
});

app.listen(PORT, () => {
    console.log("Server is running on PORT", PORT);
  });
  

