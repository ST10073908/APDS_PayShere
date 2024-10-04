import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import User from '../models/User.js'; 
import { validatePaymentInput } from '../middleware/paymentValidationMiddleware.js';

import { paymentRateLimiter } from '../middleware/rateLimitMiddleware.js';
import { ensureSSL } from '../middleware/sslMiddleware.js';

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET;

// Ensure SSL for all routes in this file
router.use(ensureSSL);

// Base route
router.get('/', (req, res) => {
    res.send('Welcome to the secure Customer Payment Portal');
});

// Registration Route
router.post('/register', async (req, res) => {
    try {
        const { firstName, lastName, phoneNumber, email, password, confirmPassword } = req.body;

        // Validate if all fields are present
        if (!firstName || !lastName || !phoneNumber || !email || !password || !confirmPassword) {
            return res.status(400).json({ message: "All fields are required" });
        }

        // Check if password and confirmPassword match
        if (password !== confirmPassword) {
            return res.status(400).json({ message: "Passwords do not match" });
        }

        // Check if the email already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "Email already exists" });
        }

        // Hash the password for security
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create a new user with the additional fields
        const newUser = new User({
            firstName,
            lastName,
            phoneNumber,
            email,
            password: hashedPassword,
            confirmPassword : hashedPassword
        });
        
        // Save the user to the database
        await newUser.save();

        return res.status(201).json({ message: "User registered successfully" });
    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err });
    }
});

// Login Route
router.post("/login", paymentRateLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find the user by username
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: "Invalid credentials" });
        }

        // Check if the password matches the hashed password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: "Invalid credentials" });
        }

        // Create a JWT token for the session
        const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "1h" });

        res.json({ token });
    } catch (err) {
        res.status(500).json({ message: "Server error", error: err });
    }
});

export default router;
