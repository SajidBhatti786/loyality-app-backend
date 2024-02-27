const axios = require("axios");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/userModel");
const jWT_SECRET = process.env.jWT_SECRET;

// Login API
const login = async (req, res) => {
  // Login logic
  const { username, password } = req.body;

  // Check if both username and password are provided
  if (!username || !password) {
    return res.status(400).json({
      status: 400,
      message: "Both username and password are required",
    });
  }

  // Find the user in the database
  let user = await User.findOne({ email: username }).lean();

  if (!user) {
    // User not found
    return res.status(404).json({
      status: 404,
      message: "Invalid username or password",
    });
  }

  // Compare the provided password with the hashed password stored in the database
  const passwordMatch = await bcrypt.compare(password, user.password);

  if (passwordMatch) {
    // Passwords match, send a successful login response
    console.log("passwords match");
    const token = jwt.sign(
      {
        id: user._id,
        username: user.email,
      },
      jWT_SECRET
    );
    console.log(token);
    console.log(user);
    const { _id, full_name, email } = user;
    const newUserObject = {
      _id,
      full_name,

      email,
    };
    return res.status(200).json({
      status: 200,
      message: "Login successful",
      user: newUserObject,
      data: token,
    });
  } else {
    // Passwords do not match
    return res.status(401).json({
      status: 401,
      message: "Invalid username or password",
    });
  }
};

// Register/SignUP API
const register = async (req, res) => {
  try {
    console.log("req body:", req.body);
    let { full_name, email, password } = req.body;
    if (!full_name || !email || !password) {
      return res.status(400).json({
        error: "Bad Request",
        message: "Missing or empty values for required fields.",
      });
    }

    // console.log("Uploaded image details:", {
    //   fieldname: my_image.fieldname,
    //   originalname: my_image.originalname,
    //   encoding: my_image.encoding,
    //   mimetype: my_image.mimetype,
    //   size: my_image.size,
    // });

    //checking if user already exists
    let user = await User.findOne({ email: email });
    if (user) {
      return res
        .status(400)
        .json({ status: 400, message: "User already exists with this email" });
    }

    // Hash the password
    password = await bcrypt.hash(password, 10);

    // Upload image to Cloudinary

    let response = await User.create({
      full_name: full_name,

      email: email.toLowerCase(),
      password: password,
    });

    return res.json({ status: 200, message: "User created successfully" });
  } catch (error) {
    console.error("Error:", error);
    if (error.code === 11000) {
      return res.json({ status: 11000, message: "Username already exists" });
    }
    let validationErrors = [];
    if (error.errors) {
      for (const key in error.errors) {
        validationErrors.push(error.errors[key].message);
      }
      return res.status(400).json({ status: 400, messages: validationErrors });
    }
    return res.json({ status: "error", message: "Format issue" });
  }
};

module.exports = {
  login,
  register,
};
