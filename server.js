// server.js

// 1. Import Dependencies
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// --- Final, Explicit CORS Configuration ---
// This manually sets the headers to handle the OPTIONS preflight request.
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*'); // Allows any origin
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With,content-type,Authorization');
  res.setHeader('Access-Control-Allow-Credentials', true);

  // Handle the OPTIONS preflight request
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

app.use(express.json());

// --- Middleware to verify JWT ---
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

// Admin middleware
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

// --- MongoDB Connection ---
const MONGO_URI = "mongodb+srv://Vivek2345:connect7890@memberportalcluster.v4qvgpf.mongodb.net/";

mongoose.connect(MONGO_URI)
    .then(() => console.log("MongoDB connected successfully"))
    .catch(err => console.error("MongoDB connection error:", err));

// --- Database Schemas ---

// User Schema
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    mobile: String,
    dob: Date,
    status: { type: String, enum: ['pending', 'active'], default: 'pending' },
    transactionId: { type: String },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    joiningDate: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

// Activity Schema
const activitySchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String, required: true },
    date: { type: Date, required: true },
    createdAt: { type: Date, default: Date.now }
});
const Activity = mongoose.model('Activity', activitySchema);

// Discount Request Schema
const discountRequestSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    eventTitle: { type: String, required: true },
    status: { type: String, enum: ['pending', 'approved', 'denied'], default: 'pending' },
    requestedAt: { type: Date, default: Date.now }
});
const DiscountRequest = mongoose.model('DiscountRequest', discountRequestSchema);

// --- Health Check Endpoint ---
app.get('/', (req, res) => {
    res.send('Backend server is live and running!');
});

// --- API Endpoints ---

// 1. Registration Endpoint
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
        console.error("Registration Error:", err.message);
        res.status(500).send('Server Error');
    }
});

// 2. Login Endpoint
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ msg: 'Invalid credentials.' });
        }
        if (user.status !== 'active') {
            return res.status(403).json({ msg: 'Your account has not been approved by the admin yet.' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ msg: 'Invalid credentials.' });
        }
        const payload = { user: { id: user.id, role: user.role } };
        const JWT_SECRET = process.env.JWT_SECRET || 'a_default_secret_key';
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' });
        res.json({ token, role: user.role });
    } catch (err) {
        res.status(500).send('Server Error');
    }
});

// 3. User Portal Data Endpoint
app.get('/api/portal-data', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.user.id).select('-password');
        const activities = await Activity.find().sort({ date: 1 });
        res.json({ user, activities });
    } catch (err) {
        res.status(500).send('Server Error');
    }
});

// 4. Discount Request Endpoint
app.post('/api/request-discount', authMiddleware, async (req, res) => {
    try {
        const { eventTitle } = req.body;
        const newRequest = new DiscountRequest({ user: req.user.user.id, eventTitle });
        await newRequest.save();
        res.status(201).json({ msg: 'Discount request submitted successfully!' });
    } catch (err) {
        res.status(500).send('Server Error');
    }
});

// --- Admin Endpoints ---

// Get all data for admin dashboard
app.get('/api/admin/dashboard', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const activities = await Activity.find().sort({ date: -1 });
        const requests = await DiscountRequest.find().populate('user', 'name email').sort({ requestedAt: -1 });
        const users = await User.find().sort({ joiningDate: -1 });
        res.json({ activities, requests, users });
    } catch (err) { res.status(500).send('Server Error'); }
});

// Approve a pending user
app.patch('/api/admin/approve-user/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const user = await User.findByIdAndUpdate(req.params.id, { status: 'active' }, { new: true });
        if (!user) return res.status(404).json({ msg: 'User not found' });
        res.json({ msg: 'User approved successfully' });
    } catch (err) { res.status(500).send('Server Error'); }
});

// Deny and delete a pending user
app.delete('/api/admin/deny-user/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        if (!await User.findByIdAndDelete(req.params.id)) {
            return res.status(404).json({ msg: 'User not found' });
        }
        res.json({ msg: 'User denied and deleted' });
    } catch (err) { res.status(500).send('Server Error'); }
});

// Create a new activity
app.post('/api/admin/activities', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { title, description, date } = req.body;
        const newActivity = new Activity({ title, description, date });
        await newActivity.save();
        res.status(201).json(newActivity);
    } catch (err) { res.status(500).send('Server Error'); }
});

// Delete an activity
app.delete('/api/admin/activities/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        if (!await Activity.findByIdAndDelete(req.params.id)) {
             return res.status(404).json({ msg: 'Activity not found' });
        }
        res.json({ msg: 'Activity deleted' });
    } catch (err) { res.status(500).send('Server Error'); }
});

// Update a discount request
app.patch('/api/admin/requests/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { status } = req.body;
        const request = await DiscountRequest.findByIdAndUpdate(req.params.id, { status }, { new: true });
        if(!request) return res.status(404).json({msg: 'Request not found'});
        res.json(request);
    } catch (err) { res.status(500).send('Server Error'); }
});

// Start the Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
