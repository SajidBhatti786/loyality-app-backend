const express = require("express");
const router = express.Router();

const authController = require("../controllers/authController");
const authMiddleware = require("../middleware/authMiddleware");

router.post("/login", authController.login);
router.post("/register", authController.register);
// router.get("/logout", authMiddleware.verifyToken, authController.logout);
module.exports = router;
