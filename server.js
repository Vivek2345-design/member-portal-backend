// server.js

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// --- CORS Configuration ---
app.use(cors());
app.use(express.json());

// --- MongoDB Connection ---
const MONGO_URI = process.env.MONGO_URI || "mongodb+srv://Vivek2345:connect7890@memberportalcluster.v4qvgpf.mongodb.net/";
mongoose.connect(MONGO_URI)
    .then(() => console.log("MongoDB connected successfully"))
    .catch(err => console.error("MongoDB connection error:", err));

// --- Database Schemas ---

// 1. User Schema with Roles
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    mobile: String,
    dob: Date,
    status: { type: String, enum: ['pending', 'active'], default: 'pending' },
    transactionId: { type: String },
    role: { type: String, enum: ['user', 'admin'], default: 'user' } // New role field
});
const User = mongoose.model('User', userSchema);

// 2. Activity Schema
const activitySchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String, required: true },
    date: { type: Date, required: true },
    createdAt: { type: Date, default: Date.now }
});
const Activity = mongoose.model('Activity', activitySchema);

// 3. Discount Request Schema
const discountRequestSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    eventTitle: { type: String, required: true },
    status: { type: String, enum: ['pending', 'approved', 'denied'], default: 'pending' },
    requestedAt: { type: Date, default: Date.now }
});
const DiscountRequest = mongoose.model('DiscountRequest', discountRequestSchema);


// --- Middleware ---

// Auth middleware (to check if user is logged in)
const authMiddleware = (req, res, next) => {
    const authHeader = req.header('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ msg: 'No token, authorization denied' });
    }
    try {
        const token = authHeader.split(' ')[1];
        const JWT_SECRET = process.env.JWT_SECRET || 'a_default_secret_key';
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (err) {
        res.status(401).json({ msg: 'Token is not valid' });
    }
};

// Admin middleware (to check if user is an admin)
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

// Registration Endpoint
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password, mobile, dob } = req.body;
        if (!name || !email || !password) {
            return res.status(400).json({ msg: 'Please enter all required fields.' });
        }
        if (await User.findOne({ email })) {
            return res.status(400).json({ msg: 'User with this email already exists.' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ name, email, password: hashedPassword, mobile, dob });
        await newUser.save();
        res.status(201).json({ msg: 'User created. Please proceed to payment.' });
    } catch (err) {
        console.error("Registration Error:", err.message);
        res.status(500).send('Server Error');
    }
});

// Activation Endpoint
app.post('/api/activate', async (req, res) => {
    try {
        const { email, transactionId } = req.body;
        if (!email || !transactionId) {
            return res.status(400).json({ msg: 'Missing email or transaction ID.' });
        }
        const user = await User.findOneAndUpdate(
            { email: email },
            { status: 'active', transactionId: transactionId },
            { new: true }
        );
        if (!user) return res.status(404).json({ msg: 'User not found.' });
        res.json({ msg: 'Account activated successfully!' });
    } catch (err) {
        console.error("Activation Error:", err.message);
        res.status(500).send('Server Error');
    }
});

// Login Endpoint
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user || user.status !== 'active') {
            return res.status(400).json({ msg: 'Invalid credentials or account not active.' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ msg: 'Invalid credentials' });
        }
        const payload = { user: { id: user.id, role: user.role } };
        const token = jwt.sign(payload, process.env.JWT_SECRET || 'a_default_secret_key', { expiresIn: '8h' });
        res.json({ token, role: user.role });
    } catch (err) {
        console.error("Login Error:", err.message);
        res.status(500).send('Server Error');
    }
});


// --- User CRM Portal Endpoints ---
app.get('/api/portal-data', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.user.id).select('-password');
        const activities = await Activity.find().sort({ date: 1 });
        res.json({ user, activities });
    } catch (err) {
        console.error("Portal Data Error:", err.message);
        res.status(500).send('Server Error');
    }
});

app.post('/api/request-discount', authMiddleware, async (req, res) => {
    try {
        const { eventTitle } = req.body;
        const newRequest = new DiscountRequest({
            user: req.user.user.id,
            eventTitle
        });
        await newRequest.save();
        res.status(201).json({ msg: 'Discount request submitted successfully!' });
    } catch (err) {
        console.error("Discount Request Error:", err.message);
        res.status(500).send('Server Error');
    }
});


// --- Admin CRM Portal Endpoints ---

// Get all data for admin dashboard
app.get('/api/admin/dashboard', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const activities = await Activity.find().sort({ date: -1 });
        const requests = await DiscountRequest.find().populate('user', 'name email').sort({ requestedAt: -1 });
        res.json({ activities, requests });
    } catch (err) {
        console.error("Admin Dashboard Error:", err.message);
        res.status(500).send('Server Error');
    }
});

// Create a new activity
app.post('/api/admin/activities', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { title, description, date } = req.body;
        const newActivity = new Activity({ title, description, date });
        await newActivity.save();
        res.status(201).json(newActivity);
    } catch (err) {
        console.error("Create Activity Error:", err.message);
        res.status(500).send('Server Error');
    }
});

// Delete an activity
app.delete('/api/admin/activities/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        await Activity.findByIdAndDelete(req.params.id);
        res.json({ msg: 'Activity deleted' });
    } catch (err) {
        console.error("Delete Activity Error:", err.message);
        res.status(500).send('Server Error');
    }
});

// Update a discount request status
app.patch('/api/admin/requests/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { status } = req.body;
        const updatedRequest = await DiscountRequest.findByIdAndUpdate(req.params.id, { status }, { new: true });
        res.json(updatedRequest);
    } catch (err) {
        console.error("Update Request Error:", err.message);
        res.status(500).send('Server Error');
    }
});


// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server started on port ${PORT}`));

