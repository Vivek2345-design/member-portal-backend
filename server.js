// server.js

// 1. Import Dependencies
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config(); // To use environment variables

// --- Middleware to verify JWT ---
const authMiddleware = (req, res, next) => {
    // Get token from header
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


// 2. Initialize Express App
const app = express();
// --- Configure CORS to allow your live website to make requests ---
const corsOptions = {
    origin: 'https://runwithme.club/' // IMPORTANT: Replace with your actual website URL
};
app.use(cors(corsOptions));// Allow requests from your frontend
app.use(express.json()); // Allow server to accept JSON data

// 3. Connect to MongoDB
const MONGO_URI = "mongodb+srv://Vivek2345:connect7890@memberportalcluster.v4qvgpf.mongodb.net/";

mongoose.connect(MONGO_URI)
    .then(() => console.log("MongoDB connected successfully"))
    .catch(err => console.error("MongoDB connection error:", err));

// 4. Define the User Schema and Model
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    mobile: String,
    gender: String,
    dob: Date,
    address: String,
});
const User = mongoose.model('User', userSchema);

// --- 5. API Endpoints ---

// Registration Endpoint
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password, mobile, gender, dob, address } = req.body;

        // Check if user already exists
        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ msg: 'User already exists' });
        }

        // Hash the password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create and save new user
        user = new User({
            name,
            email,
            password: hashedPassword,
            mobile,
            gender,
            dob,
            address
        });
        await user.save();

        res.status(201).json({ msg: 'User registered successfully' });

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// Login Endpoint
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Check for user
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ msg: 'Invalid credentials' });
        }

        // Compare password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ msg: 'Invalid credentials' });
        }

        // Create and return a JWT (JSON Web Token)
        const payload = { user: { id: user.id } };
        const JWT_SECRET = process.env.JWT_SECRET || 'a_default_secret_key';

        jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' }, (err, token) => {
            if (err) throw err;
            res.json({ token });
        });

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// Protected CRM Data Endpoint
app.get('/api/portal-data', authMiddleware, async (req, res) => {
    try {
        // req.user.id comes from the authMiddleware after it decodes the token
        const user = await User.findById(req.user.id).select('-password'); // Find user but exclude password
        if (!user) {
            return res.status(404).json({ msg: 'User not found' });
        }
        
        // Send back user's name and any other portal data
        res.json({
            name: user.name,
            // You can add more data here like activities, discounts etc.
        });

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});


// 6. Start the Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
