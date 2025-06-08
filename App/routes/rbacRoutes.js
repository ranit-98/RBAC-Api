const express = require("express");
const router = express.Router();

const authController = require("../controller/authController");
const { auth, adminAuth } = require("../middleware/RoleAuth"); 
const imageUpload = require('../helper/fileUpload'); 
//--------------------------------------------------------------------------------------
// Public Routes 
//--------------------------------------------------------------------------------------

router.post('/register', imageUpload.single('profileImage'), authController.register);
router.post("/verify-otp", authController.verifyOtp);
router.post("/login", authController.login);
router.post('/reset-password-link',authController.resetPasswordLink);
router.post('/reset-password/:id/:token',authController.resetPassword);

//--------------------------------------------------------------------------------------
// Protected Routes (Require authentication)
//--------------------------------------------------------------------------------------

router.get("/profile", auth, authController.getProfile);
router.put('/profile', auth, imageUpload.single('profileImage'), authController.updateProfile);



module.exports = router;
