const axios = require("axios");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/userModel");
const jWT_SECRET = process.env.jWT_SECRET;
const Loyalty = require("../models/loyaltyModel");

// Loyalty Info API
const loyaltyInfo = async (req, res) => {
  try {
    // Assuming the decoded object is added by the verifyToken middleware
    const userId = req.decoded.id;
    
    // Check if the user exists
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
    const loyaltyInfo = await Loyalty.findOne({
      userReference: userId,
    });
    

    if (!loyaltyInfo) {
      return res.status(404).json({ message: "Loyalty not found" });
    }

    const response = {
      full_name: user.full_name,
      loyalty_balance: loyaltyInfo.loyalty_balance,
      loyalty_level: loyaltyInfo.loyalty_level,
    };

    return res.status(200).json({ response });
  } catch (err) {
    console.error('Error fetching loyalty information:', err);
    return res.status(500).json({ error: "Internal Server Error" });
  }
};

module.exports = {
  loyaltyInfo,
};
