const express = require('express');
const router = express.Router();

const loyaltyController = require('../controllers/loyaltyController');
const authMiddleware = require('../middleware/authMiddleware');

// Route to get transaction history for the user
router.get('/dashboard', authMiddleware.authenticationVerifier, loyaltyController.loyaltyInfo);
// router.post('/make-transaction', authMiddleware.authenticationVerifier, transactionController.makeTransaction);

module.exports = router;
