//--------------------------------------------------------------------------------------
//                            Function to Send Email Verification OTP
//--------------------------------------------------------------------------------------

const transporter = require("../config/emailConfig");
const otpVerifyModel = require("../models/OtpModel");

//--------------------------------------------------------------------------------------
//                            Function to Send Email Verification OTP
//--------------------------------------------------------------------------------------

const sendEmailVerificationOTP = async (req, user) => {
  //--------------------------------------------------------------------------------------
  //                   Step 1: Generate a 4-digit Random OTP
  //--------------------------------------------------------------------------------------
  const otp = Math.floor(1000 + Math.random() * 9000); 

  //--------------------------------------------------------------------------------------
  //                   Step 2: Save the OTP with Associated User ID in DB
  //--------------------------------------------------------------------------------------
  const savedOTP = await new otpVerifyModel({
    userId: user._id,
    otp: otp,
  }).save();

  console.log("OTP saved to DB:", savedOTP);

  //--------------------------------------------------------------------------------------
  //                     Step 3: Send the OTP to User's Email Address
  //--------------------------------------------------------------------------------------
  await transporter.sendMail({
    from: process.env.EMAIL_FROM, 
    to: user.email, 
    subject: "OTP - Verify your account", 
    html: `
            <p>Dear ${user.name},</p>
            <p>Thank you for signing up with our website. To complete your registration, please verify your email address by entering the following one-time password (OTP):</p>
            <h2>OTP: ${otp}</h2>
            <p>This OTP is valid for 15 minutes. If you didn't request this OTP, please ignore this email.</p>
        `,
  });

  //--------------------------------------------------------------------------------------
  //                           Step 4: Return the Generated OTP
  //--------------------------------------------------------------------------------------
  return otp;
};

module.exports = sendEmailVerificationOTP;
