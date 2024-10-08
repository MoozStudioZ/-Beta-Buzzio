const express = require('express');
const {
  registerUser,
  verifyEmail,
  loginUser,
  forgotPassword,
  resetPassword
} = require('../controllers/authController');
const router = express.Router();

// Register
router.post('/register', registerUser);

// Verify email
router.get('/verify/:token', verifyEmail);

// Login
router.post('/login', loginUser);

// Forgot password
router.post('/forgot-password', forgotPassword);

// Reset password
router.put('/reset-password/:token', resetPassword);

module.exports = router;
