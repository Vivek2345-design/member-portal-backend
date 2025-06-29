// server.js

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Razorpay = require('razorpay');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// --- MongoDB Connection ---
const MONGO_URI = "mongodb+srv://Vivek2345:connect7890@memberportalcluster.v4qvgpf.mongodb.net/";
mongoose.connect(MONGO_URI).then(() => console.log("MongoDB connected")).catch(err => console.error(err));

// --- Initialize Razorpay ---
const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// --- Schemas & Models ---
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    mobile: String, 
    dob: Date,
    status: { type: String, enum: ['active'], default: 'active' }, 
    razorpayPaymentId: { type: String },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    joiningDate: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);
// Other schemas from previous steps can be added here if needed for the admin portal
const postSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String },
    link: { type: String },
    postType: { type: String, enum: ['activity', 'event', 'merchandise', 'social'], required: true },
    status: { type: String, enum: ['draft', 'published'], default: 'draft' },
    createdAt: { type: Date, default: Date.now }
});
const Post = mongoose.model('Post', postSchema);

const discountRequestSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    eventTitle: { type: String, required: true },
    status: { type: String, enum: ['pending', 'approved', 'denied'], default: 'pending' },
    response: { type: String },
    adminNotes: { type: String },
    requestedAt: { type: Date, default: Date.now }
});
const DiscountRequest = mongoose.model('DiscountRequest', discountRequestSchema);


// --- Middleware ---
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
app.get('/', (req, res) => res.send('Backend server is live!'));

// 1. Create Razorpay Order
app.post('/api/create-order', async (req, res) => {
    try {
        const options = {
            // --- AMOUNT CHANGED FOR TESTING ---
            amount: 1 * 100, // Amount in paise (₹1)
            currency: "INR",
            receipt: `receipt_order_${new Date().getTime()}`,
        };
        const order = await razorpay.orders.create(options);
        res.json(order);
    } catch (err) { 
        console.error("Error creating Razorpay order:", err);
        res.status(500).send('Server Error'); 
    }
});

// 2. Verify Payment & Complete Registration
app.post('/api/complete-registration', async (req, res) => {
    try {
        const { registrationDetails, paymentDetails } = req.body;
        const shasum = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET);
        shasum.update(`${paymentDetails.razorpay_order_id}|${paymentDetails.razorpay_payment_id}`);
        const digest = shasum.digest('hex');

        if (digest !== paymentDetails.razorpay_signature) {
            return res.status(400).json({ msg: 'Transaction not legitimate!' });
        }
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
        });
        await newUser.save();
        res.status(201).json({ msg: 'Registration successful!' });
    } catch (err) { res.status(500).send('Server Error'); }
});

// 3. Login
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

// 4. User Portal Data
app.get('/api/portal-data', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.user.id).select('-password');
        const posts = await Post.find({ status: 'published' }).sort({ createdAt: -1 });
        const discountRequests = await DiscountRequest.find({ user: req.user.user.id }).sort({ requestedAt: -1 });
        const portalData = {
            activities: posts.filter(p => p.postType === 'activity'),
            events: posts.filter(p => p.postType === 'event'),
            merchandise: posts.filter(p => p.postType === 'merchandise'),
            socials: posts.filter(p => p.postType === 'social'),
        };
        res.json({ user, portalData, discountRequests });
    } catch (err) { res.status(500).send('Server Error'); }
});


// 5. Admin Portal Data
app.get('/api/admin/dashboard', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const users = await User.find().sort({ joiningDate: -1 });
        const posts = await Post.find().sort({ createdAt: -1 });
        const requests = await DiscountRequest.find().populate('user', 'name email').sort({ requestedAt: -1 });
        res.json({ users, posts, requests });
    } catch (err) { res.status(500).send('Server Error'); }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
