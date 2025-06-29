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
const MONGO_URI = "mongodb+srv://Vivek2345:connect7890@memberportalcluster.v4qvgpf.mongodb.net/";
mongoose.connect(MONGO_URI).then(() => console.log("MongoDB connected")).catch(err => console.error(err));

// --- Database Schemas ---

// User Schema (no changes needed)
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    mobile: String, dob: Date,
    status: { type: String, enum: ['pending', 'active'], default: 'pending' },
    transactionId: { type: String },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    joiningDate: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

// NEW: Generic Post Schema for all content types
const postSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String },
    link: { type: String }, // For social links or event URLs
    postType: { type: String, enum: ['activity', 'event', 'merchandise', 'social'], required: true },
    status: { type: String, enum: ['draft', 'published'], default: 'draft' },
    createdAt: { type: Date, default: Date.now }
});
const Post = mongoose.model('Post', postSchema);

// Discount Request Schema (no changes needed)
const discountRequestSchema = new mongoose.Schema({ /* ... */ });
const DiscountRequest = mongoose.model('DiscountRequest', discountRequestSchema);


// --- Middleware ---
const authMiddleware = (req, res, next) => { /* ... existing code ... */ };
const adminMiddleware = async (req, res, next) => { /* ... existing code ... */ };


// --- API Endpoints ---
app.post('/api/register', async (req, res) => { /* ... existing code ... */ });
app.post('/api/login', async (req, res) => { /* ... existing code ... */ });

// --- User CRM Portal Endpoints ---
app.get('/api/portal-data', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.user.id).select('-password');
        // Fetch only published posts, categorized by type
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

app.post('/api/request-discount', authMiddleware, async (req, res) => { /* ... existing code ... */ });


// --- Admin CRM Portal Endpoints ---

// Get all data for admin dashboard
app.get('/api/admin/dashboard', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const users = await User.find().sort({ joiningDate: -1 });
        const posts = await Post.find().sort({ createdAt: -1 });
        const requests = await DiscountRequest.find().populate('user', 'name email').sort({ requestedAt: -1 });
        res.json({ users, posts, requests });
    } catch (err) { res.status(500).send('Server Error'); }
});

// Create a new post (for any content type)
app.post('/api/admin/posts', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { title, description, link, postType } = req.body;
        const newPost = new Post({ title, description, link, postType });
        await newPost.save();
        res.status(201).json(newPost);
    } catch (err) { res.status(500).send('Server Error'); }
});

// Update an existing post (for editing)
app.put('/api/admin/posts/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { title, description, link } = req.body;
        const updatedPost = await Post.findByIdAndUpdate(req.params.id, { title, description, link }, { new: true });
        res.json(updatedPost);
    } catch (err) { res.status(500).send('Server Error'); }
});

// Update post status (for publishing/unpublishing)
app.patch('/api/admin/posts/:id/status', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { status } = req.body;
        const updatedPost = await Post.findByIdAndUpdate(req.params.id, { status }, { new: true });
        res.json(updatedPost);
    } catch (err) { res.status(500).send('Server Error'); }
});

// Delete a post
app.delete('/api/admin/posts/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        await Post.findByIdAndDelete(req.params.id);
        res.json({ msg: 'Post deleted' });
    } catch (err) { res.status(500).send('Server Error'); }
});


// User management endpoints...
app.patch('/api/admin/approve-user/:id', authMiddleware, adminMiddleware, async (req, res) => { /* ... existing code ... */ });
app.delete('/api/admin/deny-user/:id', authMiddleware, adminMiddleware, async (req, res) => { /* ... existing code ... */ });
app.patch('/api/admin/requests/:id', authMiddleware, adminMiddleware, async (req, res) => { /* ... existing code ... */ });


// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
