// validationSchemas.js

const Joi = require("joi");

const registerSchema = Joi.object({
  name: Joi.string().min(2).max(50).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
  phone: Joi.string().optional(),
  address: Joi.object({
    street: Joi.string().optional(),
    city: Joi.string().optional(),
    state: Joi.string().optional(),
    postalCode: Joi.string().optional(),
    country: Joi.string().optional(),
  }).optional(),
  gender: Joi.string().valid("male", "female", "other").optional(),
  dateOfBirth: Joi.date().optional(),
  role: Joi.string().valid("admin", "user").default("user"),
});

const otpVerifySchema = Joi.object({
  email: Joi.string().email().required(),
  otp: Joi.string().length(4).required(),
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
});


const updateProfileSchema = Joi.object({
  name: Joi.string().min(2).max(50).optional(),
  phone: Joi.string().optional(),
  address: Joi.object({
    street: Joi.string().optional(),
    city: Joi.string().optional(),
    state: Joi.string().optional(),
    postalCode: Joi.string().optional(),
    country: Joi.string().optional(),
  }).optional(),
  gender: Joi.string().valid("male", "female", "other").optional(),
  dateOfBirth: Joi.date().optional(),
  profileImage: Joi.string().optional(), 
});


module.exports = {
  registerSchema,
  otpVerifySchema,
  loginSchema,
  updateProfileSchema
};
