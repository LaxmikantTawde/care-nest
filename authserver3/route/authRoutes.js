const express = require('express');
const mongoose = require('mongoose');
const router = express.Router();
const Baby = mongoose.model('Baby');
const Parent = mongoose.model('Parent');
const jwt = require('jsonwebtoken');
const { jwtKey } = require('../config');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const verifyToken = require('../middleware/requireToken'); 

// Configure Nodemailer
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'emailid by which you want to send mail',
    pass: 'password',  // Use a secure method for this in production
  },
});

// Baby Registration Endpoint
router.post('/api/babies', async (req, res) => {
  const { name, age, weight, height, gender } = req.body;

  try {
    const newBaby = new Baby({ name, age, weight, height, gender });
    await newBaby.save();

    req.session.babyId = newBaby._id;  // Store babyId in the session
    res.status(201).json({ babyId: newBaby._id });
  } catch (err) {
    console.error("Error details:", err);
    res.status(400).json({ error: 'Error saving baby information.' });
  }
});

// Parent Registration Endpoint
router.post('/api/parents', async (req, res) => {
  const { name, mobileNo, email, password } = req.body;
  const babyId = req.session.babyId;  // Retrieve babyId from session

  if (!babyId) {
    return res.status(400).json({ error: 'Baby ID is required to create a parent record' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newParent = new Parent({ name, mobileNo, email, password: hashedPassword, babyId });
    await newParent.save();

    const token = jwt.sign({ userId: newParent._id }, jwtKey, { expiresIn: '1h' });
    res.status(201).json({ token });
  } catch (err) {
    console.error("Error details:", err);
    res.status(400).json({ error: 'Error saving parent information.' });
  }
});

// Sign-in Endpoint
router.post('/signin', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(422).json({ error: "Must provide email or password" });
  }

  const user = await Parent.findOne({ email });
  if (!user) {
    return res.status(422).json({ error: "Invalid email or password" });
  }

  try {
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(422).json({ error: "Invalid email or password" });
    }
    const token = jwt.sign({ userId: user._id }, jwtKey);
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// Forgot Password Endpoint
router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;

  try {
    const user = await Parent.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: 'User with this email does not exist' });
    }

    // Generate a password reset token
    const token = jwt.sign({ userId: user._id }, jwtKey, { expiresIn: '1h' });
    user.resetPasswordToken = token;
    user.resetPasswordExpires = Date.now() + 3600000; // Token expires in 1 hour
    await user.save();

    const resetUrl = `http://10.0.2.2:5000/reset-password?token=${token}`;

    const mailOptions = {
      to: email,
      from: 'emailid by which you want to send mail',
      subject: 'Password Reset Request',
      html: `<p>You requested a password reset</p>
             <p>Click this <a href="${resetUrl}">link</a> to reset your password.</p>`
    };

    transporter.sendMail(mailOptions, (err) => {
      if (err) {
        return res.status(500).json({ error: 'Error sending email' });
      }
      res.status(200).json({ message: 'Password reset email sent', token });
    });
  } catch (err) {
    res.status(500).json({ error: 'Error processing request' });
  }
});

// Reset Password Endpoint
router.post('/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  const { newPassword } = req.body;

  if (!newPassword) {
    return res.status(400).json({ error: 'New password is required' });
  }

  try {
    
    const decoded = jwt.verify(token, jwtKey);

  
    const user = await Parent.findOne({
      _id: decoded.userId,
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ error: 'Password reset failed. Please try again.' });
    }


    user.password = newPassword;
    await user.save(); 
    res.status(200).json({ message: 'Password has been reset successfully' });
  } catch (err) {
    console.error('Error processing request:', err);
    res.status(500).json({ error: 'Error processing request' });
  }
});


router.get('/reset-password', (req, res) => {
  const { token } = req.query;

  // Return an HTML form with method POST, targeting the correct URL
  res.send(`
    <html>
      <head>
        <style>
          body {
            font-family: Arial, sans-serif;
            background-color: #f4f7fc;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
          }
          .reset-container {
            background-color: #fff;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            width: 100%;
            max-width: 400px;
          }
          h3 {
            text-align: center;
            color: #333;
          }
          .form-group {
            margin-bottom: 20px;
          }
          label {
            font-size: 14px;
            color: #555;
            display: block;
            margin-bottom: 5px;
          }
          input[type="password"] {
            width: 100%;
            padding: 10px;
            font-size: 14px;
            border: 1px solid #ddd;
            border-radius: 4px;
          }
          button[type="submit"] {
            width: 100%;
            padding: 10px;
            background-color: #4CAF50;
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 16px;
            cursor: pointer;
          }
          button[type="submit"]:hover {
            background-color: #45a049;
          }
          .reset-container p {
            text-align: center;
            font-size: 14px;
            color: #555;
          }
        </style>
      </head>
      <body>
        <div class="reset-container">
          <h3>Reset Your Password</h3>
          <form action="/reset-password/${token}" method="POST">
            <div class="form-group">
              <label for="newPassword">New Password</label>
              <input type="password" id="newPassword" name="newPassword" required placeholder="Enter your new password" />
            </div>
            <button type="submit">Reset Password</button>
          </form>
          <p>Enter your new password and submit to reset it.</p>
        </div>
      </body>
    </html>
  `);
});

router.put('/update-baby/:babyId', verifyToken, async (req, res) => {
  const { name, age, weight, height, gender, bmi } = req.body;
  const babyId = req.params.babyId;

  try {
    // Ensure the parent is authorized to update this baby profile
    const baby = await Baby.findById(babyId);
    if (!baby) {
      return res.status(404).json({ message: 'Baby profile not found.' });
    }

    // Update the baby profile
    baby.name = name || baby.name;
    baby.age = age || baby.age;
    baby.weight = weight || baby.weight;
    baby.height = height || baby.height;
    baby.gender = gender || baby.gender;
    baby.bmi = bmi || baby.bmi;

    await baby.save();

    res.status(200).json({ message: 'Baby profile updated successfully.', baby });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error.' });
  }
});

module.exports = router;
