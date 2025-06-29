// server.js

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto'); // Built-in Node.js module for generating tokens
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const MONGO_URI = "mongodb+srv://Vivek2345:connect7890@memberportalcluster.v4qvgpf.mongodb.net/";
mongoose.connect(MONGO_URI).then(() => console.log("MongoDB connected")).catch(err => console.error(err));

// Nodemailer Transporter
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// --- UPDATED User Schema with password reset fields ---
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    mobile: String, dob: Date,
    status: { type: String, enum: ['pending', 'active'], default: 'pending' },
    transactionId: { type: String },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    joiningDate: { type: Date, default: Date.now },
    resetPasswordToken: String,
    resetPasswordExpires: Date
});
const User = mongoose.model('User', userSchema);

// Other schemas...
// ...

// --- Middleware ---
const authMiddleware = (req, res, next) => { /* ... */ };
const adminMiddleware = async (req, res, next) => { /* ... */ };

// --- API Endpoints ---
app.post('/api/register', async (req, res) => { /* ... */ });
app.post('/api/login', async (req, res) => { /* ... */ });

// --- NEW: Forgot Password Endpoint ---
app.post('/api/forgot-password', async (req, res) => {
    try {
        const user = await User.findOne({ email: req.body.email });
        if (!user) {
            // For security, don't reveal that the user does not exist
            return res.status(200).json({ msg: 'If a user with that email exists, a reset link has been sent.' });
        }
        
        const token = crypto.randomBytes(20).toString('hex');
        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
        await user.save();

        const resetURL = `https://runwithme.club/reset.html?token=${token}`;

        await transporter.sendMail({
            to: user.email,
            from: `"RunWithMeClub" <${process.env.EMAIL_USER}>`,
            subject: 'Password Reset Request',
            html: `You are receiving this because you (or someone else) have requested the reset of the password for your account.<br><br>
                   Please click on the following link, or paste this into your browser to complete the process within one hour of receiving it:<br><br>
                   <a href="${resetURL}">${resetURL}</a><br><br>
                   If you did not request this, please ignore this email and your password will remain unchanged.`
        });
        
        res.status(200).json({ msg: 'Reset email sent.' });
    } catch (err) {
        res.status(500).send('Server Error');
    }
});

// --- NEW: Reset Password Endpoint ---
app.post('/api/reset-password', async (req, res) => {
    try {
        const user = await User.findOne({
            resetPasswordToken: req.body.token,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({ msg: 'Password reset token is invalid or has expired.' });
        }

        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        user.password = hashedPassword;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();
        
        res.status(200).json({ msg: 'Password has been successfully reset.' });
    } catch (err) {
        res.status(500).send('Server Error');
    }
});


// Admin and other endpoints...
// ...

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
