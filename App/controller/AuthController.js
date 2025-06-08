const Joi = require("joi");
const User = require("../models/User");
const OtpModel = require("../models/OtpModel");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const sendEmailVerificationOTP = require("../helper/sendEmailVerificationOTP");

const { registerSchema, otpVerifySchema, loginSchema, updateProfileSchema } = require("../validation/userValidation");
const  transporter  = require("../config/emailConfig");

const asyncHandler = fn => (req, res, next) => 
  Promise.resolve(fn(req, res, next)).catch(next);

const sendError = (res, statusCode, message) =>
  res.status(statusCode).json({ statusCode, message, data: null });

//--------------------------------------------------------------------------------------
// Register Controller - Creates user with OTP and sends email
//--------------------------------------------------------------------------------------
const register = asyncHandler(async (req, res) => {
  if (!req.body) return sendError(res, 400, "Request body missing");

    if (typeof req.body.address === "string") {
    try {
      req.body.address = JSON.parse(req.body.address);
    } catch (e) {
      return sendError(res, 400, "Invalid JSON format for address");
    }
  }

  const { error } = registerSchema.validate(req.body);
  if (error) return sendError(res, 400, error.details[0].message);

  const { name, email, password, phone, address, gender, dateOfBirth, role } = req.body;

  const existingUser = await User.findOne({ email });
  if (existingUser) return sendError(res, 409, "User already exists with this email");

  const hashedPassword = await bcrypt.hash(password, 10);

  let profileImage = null;
  if (req.file) {
    profileImage = req.file.filename; 
  }

  const user = new User({
    name,
    email,
    password: hashedPassword,
    phone,
    address,
    gender,
    dateOfBirth,
    role: role || "user",
    isVerified: false,
    profileImage, 
  });

  await user.save();

  await sendEmailVerificationOTP(req, user);

  return res.status(201).json({
    statusCode: 201,
    message: "User registered successfully. Please verify OTP sent to your email.",
    data: { userId: user._id, email: user.email },
  });
});


//--------------------------------------------------------------------------------------
// OTP Verify Controller
//--------------------------------------------------------------------------------------
const verifyOtp = asyncHandler(async (req, res) => {
  if (!req.body) return sendError(res, 400, "Request body missing");

  const { error } = otpVerifySchema.validate(req.body);
  if (error) return sendError(res, 400, error.details[0].message);

  const { email, otp } = req.body;
  if (!email) return sendError(res, 400, "Email missing");

  const user = await User.findOne({ email });
  if (!user) return sendError(res, 404, "User not found");

  const otpEntry = await OtpModel.findOne({ userId: user._id }).sort({ createdAt: -1 });

  if (!otpEntry) return sendError(res, 400, "OTP not found. Please request a new one.");
  if (otpEntry.otp !== otp) return sendError(res, 400, "Invalid OTP");
  if (Date.now() > otpEntry.expiresAt) return sendError(res, 400, "OTP expired. Please request a new one.");


  await User.findByIdAndUpdate(user._id, { isVerified: true });

  await OtpModel.deleteMany({ userId: user._id });

  return res.status(200).json({
    statusCode: 200,
    message: "OTP verified successfully. You can now login.",
    data: { userId: user._id },
  });
});


//--------------------------------------------------------------------------------------
// Login Controller
//--------------------------------------------------------------------------------------
const login = asyncHandler(async (req, res) => {
  if (!req.body) return sendError(res, 400, "Request body missing");

  const { error } = loginSchema.validate(req.body);
  if (error) return sendError(res, 400, error.details[0].message);

  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) return sendError(res, 400, "Invalid credentials");
  if (!user.isVerified) {
  
    await sendEmailVerificationOTP(req, user);
    return sendError(res, 403, "Email not verified. OTP resent.");
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return sendError(res, 400, "Invalid credentials");

  const payload = { userId: user._id, role: user.role, email: user.email };
  const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "24h" });

  return res.status(200).json({
    statusCode: 200,
    message: "Login successful",
    data: {
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        profileImage: user.profileImage,
      },
    },
  });
});

//--------------------------------------------------------------------------------------
// Get Profile Controller
//--------------------------------------------------------------------------------------
const getProfile = asyncHandler(async (req, res) => {
  const userId = req.user?.userId;
  if (!userId) return sendError(res, 401, "Unauthorized");

  const user = await User.findById(userId).select("-password -otp -otpExpiresAt");
  if (!user) return sendError(res, 404, "User not found");

  return res.status(200).json({
    statusCode: 200,
    message: "Profile retrieved successfully",
    data: { user },
  });
});

//--------------------------------------------------------------------------------------
// Update Profile Controller
//--------------------------------------------------------------------------------------
const updateProfile = asyncHandler(async (req, res) => {
  const userId = req.user?.userId;
  if (!userId) return sendError(res, 401, "Unauthorized");

  const hasBodyData = req.body && Object.keys(req.body).length > 0;
  const hasFile = !!req.file;
  if (!hasBodyData && !hasFile) return sendError(res, 400, "No data to update");

  if (hasBodyData) {
    const { error } = updateProfileSchema.validate(req.body);
    if (error) return sendError(res, 400, error.details[0].message);
  }

  const user = await User.findById(userId);
  if (!user) return sendError(res, 404, "User not found");

  if (hasBodyData) {
    for (const key in req.body) {
      if (Object.prototype.hasOwnProperty.call(req.body, key)) {
        try {
          user[key] = typeof req.body[key] === "string" ? JSON.parse(req.body[key]) : req.body[key];
        } catch {
          user[key] = req.body[key];
        }
      }
    }
  }

  if (hasFile) {
    user.profileImage = req.file.filename; 
  }

  await user.save();

  return res.status(200).json({
    statusCode: 200,
    message: "Profile updated successfully",
    data: {
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        address: user.address,
        gender: user.gender,
        dateOfBirth: user.dateOfBirth,
        profileImage: user.profileImage,
        role: user.role,
      },
    },
  });
});


//--------------------------------------------------------------------------------------
//                                  Forget Password Controller
//--------------------------------------------------------------------------------------

//--------------------------------------------------------------------------------------
//                              Send Reset Password Link Controller
//--------------------------------------------------------------------------------------

const resetPasswordLink = asyncHandler(async (req, res) => {
  try {
    //--------------------------------------------------------------------------------------
    // Step 1: Validate email and check if user exists
    //--------------------------------------------------------------------------------------
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ status: false, message: "Email field is required" });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ status: false, message: "Email doesn't exist" });
    }

    //--------------------------------------------------------------------------------------
    // Step 2: Generate token and send password reset email
    //--------------------------------------------------------------------------------------
    const secret = user._id + process.env.JWT_SECRET; // <--- Unique secret for this user
    const token = jwt.sign({ userID: user._id }, secret, { expiresIn: '20m' }); // <--- Generate JWT token

    const resetLink = `${process.env.FRONTEND_HOST}/account/reset-password-confirm/${user._id}/${token}`; // <--- Frontend reset link

  await transporter.sendMail({
  from: process.env.EMAIL_FROM,
  to: user.email,
  subject: "Password Reset Link",
  html: `<p>Click <a href="${resetLink}">here</a> to reset your password.</p>`
});

    res.status(200).json({ status: true, message: "Password reset email sent. Please check your email." });

  } catch (error) {
    console.log(error);
    res.status(500).json({ status: false, message: "Unable to send password reset email. Please try again later." });
  }
});



//--------------------------------------------------------------------------------------
//                               Reset Password Controller
//--------------------------------------------------------------------------------------

const resetPassword = asyncHandler(async (req, res) => {
  try {
    //--------------------------------------------------------------------------------------
    // Step 1: Validate user and token
    //--------------------------------------------------------------------------------------
    const { password, confirm_password } = req.body;
    const { id, token } = req.params;

    // Debug log token
    console.log("Token to verify:", token);

    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({ status: false, message: "User not found" });
    }

    const new_secret = user._id + process.env.JWT_SECRET; 

    // Verify token safely
    try {
      jwt.verify(token, new_secret); // <--- Verify token
    } catch (verifyError) {
      return res.status(401).json({ status: false, message: "Invalid or expired token" });
    }

    // Validate password inputs
    if (!password || !confirm_password) {
      return res.status(400).json({ status: false, message: "New Password and Confirm New Password are required" });
    }

    if (password !== confirm_password) {
      return res.status(400).json({ status: false, message: "New Password and Confirm New Password don't match" });
    }

    //--------------------------------------------------------------------------------------
    // Step 2: Hash new password and update in database
    //--------------------------------------------------------------------------------------
    const salt = await bcrypt.genSalt(10); // <--- Generate salt
    const newHashPassword = await bcrypt.hash(password, salt); // <--- Hash password

    await User.findByIdAndUpdate(user._id, { $set: { password: newHashPassword } }); // <--- Update password in DB

    // Send success response
    res.status(200).json({ status: "success", message: "Password reset successfully" });

  } catch (error) {
    console.log(error);
    return res.status(500).json({ status: "failed", message: "Unable to reset password. Please try again later." });
  }
});


//--------------------------------------------------------------------------------------
//                               Update Password Controller
//--------------------------------------------------------------------------------------

const updatePassword = asyncHandler(async (req, res) => {
  try {
    //--------------------------------------------------------------------------------------
    // Step 1: Extract token from header and decode user ID
    //--------------------------------------------------------------------------------------
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ status: false, message: 'Unauthorized: No token provided' });
    }

    const token = authHeader.split(' ')[1];

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ status: false, message: 'Unauthorized: Invalid token' });
    }

    const user_id = decoded.userId;

    //--------------------------------------------------------------------------------------
    // Step 2: Validate password field
    //--------------------------------------------------------------------------------------
    const { password } = req.body;

    if (!password) {
      return res.status(400).json({ status: false, message: 'Password is required' });
    }

    //--------------------------------------------------------------------------------------
    // Step 3: Find user and update password
    //--------------------------------------------------------------------------------------
    const user = await User.findById(user_id);

    if (!user) {
      return res.status(404).json({ status: false, message: 'User not found' });
    }

    const hashedPassword = await HashedPassword(password); // <--- Hash new password

    await User.findByIdAndUpdate(user_id, {
      $set: { password: hashedPassword },
    });

    //--------------------------------------------------------------------------------------
    // Step 4: Send success response
    //--------------------------------------------------------------------------------------
    return res.status(200).json({
      status: true,
      message: 'Password updated successfully',
    });

  } catch (err) {
    console.log(err);
    res.status(500).json({
      status: false,
      message: 'Something went wrong while updating the password',
    });
  }
});








module.exports = {
  register,
  verifyOtp,
  login,
  getProfile,
  updateProfile,
  resetPasswordLink,
  resetPassword,
  updatePassword
};
