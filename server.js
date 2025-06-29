// server.js

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt =require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// --- MongoDB Connection ---
const MONGO_URI = "mongodb+srv://Vivek2345:connect7890@memberportalcluster.v4qvgpf.mongodb.net/";
mongoose.connect(MONGO_URI).then(() => console.log("MongoDB connected")).catch(err => console.error(err));

// --- Schemas, Models, and Middleware ---

// User Schema
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

// Post Schema
const postSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String },
    link: { type: String },
    postType: { type: String, enum: ['activity', 'event', 'merchandise', 'social'], required: true },
    status: { type: String, enum: ['draft', 'published'], default: 'draft' },
    createdAt: { type: Date, default: Date.now }
});
const Post = mongoose.model('Post', postSchema);

// Discount Request Schema
const discountRequestSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    eventTitle: { type: String, required: true },
    status: { type: String, enum: ['pending', 'approved', 'denied'], default: 'pending' },
    requestedAt: { type: Date, default: Date.now }
});
const DiscountRequest = mongoose.model('DiscountRequest', discountRequestSchema);

// Auth Middleware
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

// Admin Middleware
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

// Login Endpoint
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

// User Portal Data Endpoint
app.get('/api/portal-data', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.user.id).select('-password');
        const posts = await Post.find({ status: 'published' }).sort({ createdAt: -1 });
        const portalData = {
            activities: posts.filter(p => p.postType === 'activity'),
            events: posts.filter(p => p.postType === 'event'),
            merchandise: posts.filter(p => p.postType === 'merchandise'),
            socials: posts.filter(p => p.postType === 'social'),
        };
        res.json({ user, portalData });
    } catch (err) { res.status(500).send('Server Error'); }
});


// --- Admin CRM Portal Endpoints ---

// Get all data for admin dashboard
app.get('/api/admin/dashboard', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const users = await User.find().sort({ joiningDate: -1 });
        const posts = await Post.find().sort({ createdAt: -1 });
        const requests = await DiscountRequest.find().populate('user', 'name email').sort({ requestedAt: -1 });
        res.json({ users, posts, requests });
    } catch (err) {
        res.status(500).send('Server Error');
    }
});

// Approve User
app.patch('/api/admin/approve-user/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const user = await User.findByIdAndUpdate(req.params.id, { status: 'active' }, { new: true });
        if (!user) return res.status(404).json({ msg: 'User not found' });
        res.json({ msg: 'User approved successfully' });
    } catch (err) { res.status(500).send('Server Error'); }
});

// Deny User
app.delete('/api/admin/deny-user/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        if (!await User.findByIdAndDelete(req.params.id)) {
            return res.status(404).json({ msg: 'User not found' });
        }
        res.json({ msg: 'User denied and deleted' });
    } catch (err) { res.status(500).send('Server Error'); }
});

// Create Post
app.post('/api/admin/posts', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { title, description, link, postType, status } = req.body;
        const newPost = new Post({ title, description, link, postType, status: status || 'draft' });
        await newPost.save();
        res.status(201).json(newPost);
    } catch (err) { res.status(500).send('Server Error'); }
});

// Update Post
app.put('/api/admin/posts/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { title, description, link } = req.body;
        const updatedPost = await Post.findByIdAndUpdate(req.params.id, { title, description, link }, { new: true });
        res.json(updatedPost);
    } catch (err) { res.status(500).send('Server Error'); }
});

// Update Post Status (Publish/Unpublish)
app.patch('/api/admin/posts/:id/status', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { status } = req.body;
        const updatedPost = await Post.findByIdAndUpdate(req.params.id, { status }, { new: true });
        res.json(updatedPost);
    } catch (err) { res.status(500).send('Server Error'); }
});

// Delete Post
app.delete('/api/admin/posts/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        if (!await Post.findByIdAndDelete(req.params.id)) {
            return res.status(404).json({ msg: 'Post not found' });
        }
        res.json({ msg: 'Post deleted' });
    } catch (err) { res.status(500).send('Server Error'); }
});

// Update Discount Request Status
app.patch('/api/admin/requests/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { status } = req.body;
        const request = await DiscountRequest.findByIdAndUpdate(req.params.id, { status }, { new: true });
        if(!request) return res.status(404).json({msg: 'Request not found'});
        res.json(request);
    } catch (err) { res.status(500).send('Server Error'); }
});


// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
