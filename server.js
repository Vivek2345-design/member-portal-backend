// server.js

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Razorpay = require('razorpay'); // Import Razorpay
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// --- MongoDB Connection ---
const MONGO_URI = "mongodb+srv://Vivek2345:connect7890@memberportalcluster.v4qvgpf.mongodb.net/";
mongoose.connect(MONGO_URI).then(() => console.log("MongoDB connected")).catch(err => console.error(err));

// --- Initialize Razorpay ---
// Make sure to set these in your Render environment variables
const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// --- Schemas & Models ---
// User schema now defaults to active status upon creation.
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    mobile: String, dob: Date,
    status: { type: String, enum: ['pending', 'active'], default: 'active' }, 
    razorpayPaymentId: { type: String },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    joiningDate: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);
// Note: Other schemas for admin portal can remain if needed.

// --- Middleware (authMiddleware, adminMiddleware can remain for portal access) ---
const authMiddleware = (req, res, next) => {
    const authHeader = req.header('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ msg: 'No token, authorization denied' });
    try {
        const token = authHeader.split(' ')[1];
        req.user = jwt.verify(token, process.env.JWT_SECRET || 'a_default_secret_key');
        next();
    } catch (err) { res.status(401).json({ msg: 'Token is not valid' }); }
};

const adminMiddleware = async (req, res, next) => {
    try {
        const user = await User.findById(req.user.user.id);
        if (user.role !== 'admin') return res.status(403).json({ msg: 'Access denied.' });
        next();
    } catch (err) { res.status(500).send('Server Error'); }
};


// --- API Endpoints ---

// 1. Create Razorpay Order
app.post('/api/create-order', async (req, res) => {
    try {
        const options = {
            amount: 999 * 100, // Amount in the smallest currency unit (paise for INR)
            currency: "INR",
            receipt: `receipt_order_${new Date().getTime()}`,
        };
        const order = await razorpay.orders.create(options);
        if (!order) return res.status(500).send('Error creating order');
        res.json(order);
    } catch (err) {
        console.error("Create Order Error:", err);
        res.status(500).send('Server Error');
    }
});

// 2. Verify Payment & Complete Registration
app.post('/api/complete-registration', async (req, res) => {
    try {
        const { registrationDetails, paymentDetails } = req.body;

        // Step A: Verify the payment signature (crucial for security)
        const shasum = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET);
        shasum.update(`${paymentDetails.razorpay_order_id}|${paymentDetails.razorpay_payment_id}`);
        const digest = shasum.digest('hex');

        if (digest !== paymentDetails.razorpay_signature) {
            return res.status(400).json({ msg: 'Transaction not legitimate!' });
        }

        // Step B: If payment is verified, create the new user
        if (await User.findOne({ email: registrationDetails.email })) {
            return res.status(400).json({ msg: 'User with this email already exists.' });
        }
        
        const hashedPassword = await bcrypt.hash(registrationDetails.password, 10);
        const newUser = new User({
            name: registrationDetails.name,
            email: registrationDetails.email,
            password: hashedPassword,
            mobile: registrationDetails.mobile,
            dob: registrationDetails.dob,
            razorpayPaymentId: paymentDetails.razorpay_payment_id,
            status: 'active' // Set status to active immediately
        });
        await newUser.save();

        res.status(201).json({ msg: 'Registration successful! Your account is now active.' });

    } catch (err) {
        console.error("Complete Registration Error:", err);
        res.status(500).send('Server Error');
    }
});

// Login and other existing endpoints...
app.post('/api/login', async (req, res) => { /* ...existing logic... */ });
app.get('/api/portal-data', authMiddleware, async (req, res) => { /* ...existing logic... */ });
// Admin endpoints can remain for managing existing users and content.

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
