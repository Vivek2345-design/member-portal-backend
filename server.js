// server.js

// 1. Import Dependencies
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

// --- FIX: Final, More Robust CORS Configuration ---
const allowedOrigins = ['https://runwithme.club', 'https://www.runwithme.club'];

const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or Postman) and from whitelisted domains
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  optionsSuccessStatus: 200 // For legacy browser support
};
// Use the CORS options
app.use(cors(corsOptions));
// Also handle pre-flight requests for all routes
app.options('*', cors(corsOptions));
// ----------------------------------------------------

app.use(express.json());

// --- MongoDB Connection ---
const MONGO_URI = "mongodb+srv://Vivek2345:connect7890@memberportalcluster.v4qvgpf.mongodb.net/";

mongoose.connect(MONGO_URI)
    .then(() => console.log("MongoDB connected successfully"))
    .catch(err => console.error("MongoDB connection error:", err));

// --- Final User Schema with status and transaction ID ---
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

// --- API Endpoints ---

// 1. Registration Endpoint
app.post('/api/register', async (req, res) => {
    console.log("Received a request to /api/register from origin:", req.headers.origin); // Debugging line
    try {
        const { name, email, password, mobile, dob } = req.body;
        if (!name || !email || !password || !mobile || !dob) {
            return res.status(400).json({ msg: 'Please enter all fields' });
        }
        if (await User.findOne({ email })) {
            return res.status(400).json({ msg: 'User with this email already exists' });
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

// 2. Activation Endpoint
app.post('/api/activate', async (req, res) => {
    try {
        const { email, transactionId } = req.body;
        if (!email || !transactionId) {
            return res.status(400).json({ msg: 'Missing email or transaction ID' });
        }
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ msg: 'User not found' });
        }
        user.status = 'active';
        user.transactionId = transactionId;
        await user.save();
        res.json({ msg: 'Account activated successfully!' });
    } catch (err) {
        console.error("Activation Error:", err.message);
        res.status(500).send('Server Error');
    }
});

// 3. Login Endpoint
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ msg: 'Invalid credentials' });
        }
        if (user.status !== 'active') {
            return res.status(403).json({ msg: 'Account not active. Please complete payment.' });
        }
        if (!await bcrypt.compare(password, user.password)) {
            return res.status(400).json({ msg: 'Invalid credentials' });
        }
        const payload = { user: { id: user.id } };
        const JWT_SECRET = process.env.JWT_SECRET || 'a_default_secret_key';
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (err) {
        console.error("Login Error:", err.message);
        res.status(500).send('Server Error');
    }
});

// 4. Protected CRM Data Endpoint
app.get('/api/portal-data', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json({ name: user.name });
    } catch (err) {
        console.error("Portal Data Error:", err.message);
        res.status(500).send('Server Error');
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
