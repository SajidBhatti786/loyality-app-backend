// Import necessary modules
const mongoose = require('mongoose');

// Define the loyalty schema
const loyaltySchema = new mongoose.Schema({
  userReference: {
    type: String,
    required: true,
    unique: true,
  },
  loyalty_balance: {
    type: Number,
    default: 0,
  },
  loyalty_level: {
    type: Number,
    default: 1,
  },
});

// Create the Loyalty model
const model = mongoose.model('Loyalty', loyaltySchema);

// Export the Loyalty model
module.exports = model;
