// server.js

const express = require('express');
const mongoose = require('mongoose');
// ... other imports

const app = express();
// ... other app setup

// --- Database Schemas ---
const userSchema = new mongoose.Schema({ /* ... */ });
const User = mongoose.model('User', userSchema);

const postSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String },
    link: { type: String },
    postType: { type: String, enum: ['activity', 'event', 'merchandise', 'social'], required: true },
    // Status now defaults to 'draft', but can be overridden on creation
    status: { type: String, enum: ['draft', 'published'], default: 'draft' },
    createdAt: { type: Date, default: Date.now }
});
const Post = mongoose.model('Post', postSchema);

const discountRequestSchema = new mongoose.Schema({ /* ... */ });
const DiscountRequest = mongoose.model('DiscountRequest', discountRequestSchema);

// --- Middleware ---
// ...

// --- API Endpoints ---
// ...

// --- Admin CRM Portal Endpoints ---
app.get('/api/admin/dashboard', async (req, res) => { /* ... */ });

// Create a new post (for any content type)
app.post('/api/admin/posts', async (req, res) => {
    try {
        // Now accepts an optional 'status' field from the request body
        const { title, description, link, postType, status } = req.body;
        const newPost = new Post({ 
            title, 
            description, 
            link, 
            postType,
            status: status || 'draft' // Use provided status, or default to 'draft'
        });
        await newPost.save();
        res.status(201).json(newPost);
    } catch (err) { res.status(500).send('Server Error'); }
});

// Other admin endpoints...
// ...

// --- Start Server ---
// ...
