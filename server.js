// server.js

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

// --- Middleware to verify JWT ---
const authMiddleware = (req, res, next) => {
    const authHeader = req.header('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ msg: 'No token, authorization denied' });
    }
    try {
        const token = authHeader.split(' ')[1];
        const JWT_SECRET = process.env.JWT_SECRET || 'a_default_secret_key';
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded.user;
        next();
    } catch (err) {
        res.status(401).json({ msg: 'Token is not valid' });
    }
};

const app = express();

// Using an open CORS policy for debugging
console.log("CORS policy is set to allow all origins for debugging.");
app.use(cors());

app.use(express.json());

// --- MongoDB Connection ---
const MONGO_URI = "mongodb+srv://Vivek2345:connect7890@memberportalcluster.v4qvgpf.mongodb.net/";

mongoose.connect(MONGO_URI)
    .then(() => console.log("MongoDB connected successfully"))
    .catch(err => console.error("MongoDB connection error:", err));

// --- User Schema ---
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    mobile: String,
    dob: Date,
    status: { type: String, enum: ['pending', 'active'], default: 'pending' },
    transactionId: { type: String }
});
const User = mongoose.model('User', userSchema);


// --- NEW: Health Check Endpoint ---
// This helps verify that the server is live and reachable.
app.get('/', (req, res) => {
    console.log("Health check endpoint was hit.");
    res.send('Backend server is live and running!');
});


// --- API Endpoints ---

// 1. Registration Endpoint
app.post('/api/register', async (req, res) => {
    console.log("Received a POST request to /api/register from origin:", req.headers.origin);
    try {
        const { name, email, password, mobile, dob } = req.body;
        if (!name || !email || !password || !mobile || !dob) {
            console.log("Registration failed: Missing fields.");
            return res.status(400).json({ msg: 'Please enter all fields' });
        }
        if (await User.findOne({ email })) {
            console.log(`Registration failed: User already exists with email ${email}`);
            return res.status(400).json({ msg: 'User with this email already exists' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ name, email, password: hashedPassword, mobile, dob });
        await newUser.save();
        console.log(`Successfully registered user: ${email}`);
        res.status(201).json({ msg: 'User created. Please proceed to payment.' });
    } catch (err) {
        console.error("Registration Error:", err.message);
        res.status(500).send('Server Error');
    }
});

// Other endpoints...
app.post('/api/activate', async (req, res) => {
    // ... (activation logic)
});
app.post('/api/login', async (req, res) => {
    // ... (login logic)
});
app.get('/api/portal-data', authMiddleware, async (req, res) => {
    // ... (portal data logic)
});


const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
