const express = require('express');
const router = express.Router();

const transactionController = require('../controllers/transactionController');
const authMiddleware = require('../middleware/authMiddleware');

// Route to get transaction history for the user
router.get('/transaction-history', authMiddleware.authenticationVerifier, transactionController.getTransactionHistory);
router.post('/make-transaction', authMiddleware.authenticationVerifier, transactionController.makeTransaction);

module.exports = router;
