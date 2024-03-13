const jwt = require("jsonwebtoken");
const jWT_SECRET = process.env.jWT_SECRET;
const User = require("../models/userModel");

const authenticationVerifier = (req, res, next) => {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(403).json({ message: "No token provided" });
  }

  jwt.verify(token, jWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: "Failed to authenticate token" });
    }
    req.decoded = decoded;
    next();
  });
};

module.exports = {
  authenticationVerifier,
};
