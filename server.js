// server.js

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
// ... other imports

const app = express();
// ... app setup

// --- Schemas, Models, and Middleware remain the same ---
// ...

// --- API Endpoints ---
// ...

// --- Admin CRM Portal Endpoints ---

// Get all data for admin dashboard
app.get('/api/admin/dashboard', authMiddleware, adminMiddleware, async (req, res) => {
    console.log("Admin dashboard request received.");
    try {
        console.log("Fetching users...");
        const users = await User.find().sort({ joiningDate: -1 });
        
        console.log("Fetching posts...");
        const posts = await Post.find().sort({ createdAt: -1 });
        
        console.log("Fetching discount requests...");
        const requests = await DiscountRequest.find().populate('user', 'name email').sort({ requestedAt: -1 });
        
        console.log("All data fetched successfully. Sending response.");
        res.json({ users, posts, requests });

    } catch (err) {
        console.error("Error in /api/admin/dashboard endpoint:", err.message); // More specific logging
        res.status(500).send('Server Error while fetching dashboard data.');
    }
});

// All other endpoints remain the same...
// ...

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
