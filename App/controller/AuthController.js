const Joi = require("joi");
const User = require("../models/User");
const OtpModel = require("../models/OtpModel");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const sendEmailVerificationOTP = require("../helper/sendEmailVerificationOTP");

const { registerSchema, otpVerifySchema, loginSchema, updateProfileSchema } = require("../validation/userValidation");

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


module.exports = {
  register,
  verifyOtp,
  login,
  getProfile,
  updateProfile,
};
