const Transaction = require('../models/transactionModel');
const User = require('../models/userModel');
const Loyalty = require('../models/loyaltyModel')
const getTransactionHistory = async (req, res) => {
  try {
    // Get userId from the decoded token
    const userId = req.decoded.id;

    // Check if the user exists
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Get transaction history for the user
    const transactionHistory = await Transaction.find({ userId: userId });

    // Modify each transaction object to include the full_name
    const modifiedHistory = transactionHistory.map(transaction => ({
      ...transaction.toObject(), // Convert Mongoose document to a plain object
      full_name: user.full_name,
    }));

    return res.status(200).json({ transactionHistory: modifiedHistory });
  } catch (err) {
    console.error("Error getting transaction history:", err);
    return res.status(500).json({ error: "Internal Server Error" });
  }
};
const makeTransaction = async (req, res) => {
    try {
      // Get userId from the decoded token
      const userId = req.decoded.id;
  
      // Check if the user exists
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
  
      // Find or create loyaltyInfo for the user
      var loyaltyInfo = await Loyalty.findOne({
        userReference: userId,
      });
  
      if (!loyaltyInfo) {
        loyaltyInfo = new Loyalty({
          userReference: userId,
          loyalty_balance: 0,
          loyalty_level: 1,
        });
  
        await loyaltyInfo.save();
      }
  
      // Extract item name and price from the request body
      const { item_name, price } = req.body;
  
      // Create a new transaction
      const newTransaction = new Transaction({
        userId: userId,
        item_name: item_name,
        price: price,
      });
  
      // Save the transaction
      const savedTransaction = await newTransaction.save();
  
      // Update loyalty balance based on user level
      let loyaltyMultiplier = 0;
  
      switch (loyaltyInfo.loyalty_level) {
        case 1:
          loyaltyMultiplier = 0.05; // 5%
          break;
        case 2:
          loyaltyMultiplier = 0.1; // 10%
          break;
        case 3:
          loyaltyMultiplier = 0.15; // 15%
          break;
        case 4:
          loyaltyMultiplier = 0.2; // 20%
          break;
        default:
          loyaltyMultiplier = 0; // No additional loyalty for other levels
      }
  
      // Calculate loyalty points and update the user's loyalty balance
      const loyaltyPoints = price * loyaltyMultiplier;
    //   loyaltyInfo.loyalty_balance += loyaltyPoints;
  
      // Check and update loyalty level based on loyalty_balance
      if (loyaltyInfo.loyalty_balance > 1500) {
        loyaltyInfo.loyalty_level = 4;
      } else if (loyaltyInfo.loyalty_balance > 1000) {
        loyaltyInfo.loyalty_level = 3;
      } else if (loyaltyInfo.loyalty_balance > 500) {
        loyaltyInfo.loyalty_level = 2;
      }
  
      // Save the updated loyaltyInfo with the new loyalty balance and level
      
        loyaltyInfo.loyalty_balance= loyaltyInfo.loyalty_balance + loyaltyPoints,
        loyaltyInfo.loyalty_level= loyaltyInfo.loyalty_level,
     

      await loyaltyInfo.save();
  
      return res.status(201).json({
        message: "Transaction created successfully",
        transaction: savedTransaction,
        loyaltyPoints: loyaltyPoints,
        updatedLoyaltyBalance: loyaltyInfo.loyalty_balance,
        updatedLoyaltyLevel: loyaltyInfo.loyalty_level,
      });
    } catch (err) {
      console.error("Error making transaction:", err);
      return res.status(500).json({ error: "Internal Server Error" });
    }
  };
  
module.exports = {
  getTransactionHistory,
  makeTransaction
};
