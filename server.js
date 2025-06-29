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

// --- Schemas ---
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

const postSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String },
    link: { type: String },
    postType: { type: String, enum: ['activity', 'event', 'merchandise', 'social'], required: true },
    status: { type: String, enum: ['draft', 'published'], default: 'draft' },
    createdAt: { type: Date, default: Date.now }
});
const Post = mongoose.model('Post', postSchema);

const discountRequestSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    eventTitle: { type: String, required: true },
    status: { type: String, enum: ['pending', 'approved', 'denied'], default: 'pending' },
    requestedAt: { type: Date, default: Date.now }
});
const DiscountRequest = mongoose.model('DiscountRequest', discountRequestSchema);


// --- Middleware ---
const authMiddleware = (req, res, next) => {
    const authHeader = req.header('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ msg: 'No token, authorization denied' });
    }
    try {
        const token = authHeader.split(' ')[1];
        req.user = jwt.verify(token, process.env.JWT_SECRET || 'a_default_secret_key');
        next();
    } catch (err) {
        res.status(401).json({ msg: 'Token is not valid' });
    }
};

const adminMiddleware = async (req, res, next) => {
    try {
        const user = await User.findById(req.user.user.id);
        if (user.role !== 'admin') {
            return res.status(403).json({ msg: 'Access denied. Admin role required.' });
        }
        next();
    } catch (err) {
        res.status(500).send('Server Error');
    }
};

// --- API Endpoints ---
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password, mobile, dob, transactionId } = req.body;
        if (!name || !email || !password || !transactionId) {
            return res.status(400).json({ msg: 'Please fill all required fields.' });
        }
        if (await User.findOne({ email })) {
            return res.status(400).json({ msg: 'User with this email already exists.' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ name, email, password: hashedPassword, mobile, dob, transactionId });
        await newUser.save();
        res.status(201).json({ msg: 'Registration successful! Your account is pending admin approval.' });
    } catch (err) {
        res.status(500).send('Server Error');
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user || user.status !== 'active' || !await bcrypt.compare(password, user.password)) {
            return res.status(400).json({ msg: 'Invalid credentials or account not active.' });
        }
        const payload = { user: { id: user.id, role: user.role } };
        const token = jwt.sign(payload, process.env.JWT_SECRET || 'a_default_secret_key', { expiresIn: '8h' });
        res.json({ token, role: user.role });
    } catch (err) {
        res.status(500).send('Server Error');
    }
});

app.post('/api/forgot-password', async (req, res) => {
    try {
        const user = await User.findOne({ email: req.body.email });
        if (!user) {
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
app.get('/api/admin/dashboard', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const users = await User.find().sort({ joiningDate: -1 });
        const posts = await Post.find().sort({ createdAt: -1 });
        const requests = await DiscountRequest.find().populate('user', 'name email').sort({ requestedAt: -1 });
        res.json({ users, posts, requests });
    } catch (err) { res.status(500).send('Server Error'); }
});

// ... all other admin endpoints for creating/editing posts, users, etc.

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
