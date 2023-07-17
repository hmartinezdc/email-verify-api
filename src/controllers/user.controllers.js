const catchError = require("../utils/catchError");
const User = require("../models/User");
const EmailCode = require("../models/EmailCode");
const bcrypt = require("bcrypt");
const sendEmail = require("../utils/sendEmail");
const jwt = require('jsonwebtoken');

const getAll = catchError(async (req, res) => {
  const results = await User.findAll({ include: [EmailCode] });
  return res.json(results);
});

const create = catchError(async (req, res) => {
  const { email, password, firstName, lastName, country, image, frontBaseUrl } =
    req.body;
  const encryptedPassword = await bcrypt.hash(password, 10);
  const result = await User.create({
    email,
    password: encryptedPassword,
    firstName,
    lastName,
    country,
    image,
  });

  const code = require("crypto").randomBytes(20).toString("hex");
  const link = `${frontBaseUrl}/auth/verify_email/${code}`;

  await EmailCode.create({
    code,
    userId: result.id,
  });

  await sendEmail({
    to: email,
    subject: "Verificate email for user app",
    html: ` <h1>Hello ${firstName} ${lastName}</h1>
            <p>Please click on the link to verify your email</p>
            <div>  <a href="${link}">${link}</a></div>
            <p><b>Thanks for register in our app</b></p>
    `,
  });
  return res.status(201).json(result);
});

const getOne = catchError(async (req, res) => {
  const { id } = req.params;
  const result = await User.findByPk(id);
  if (!result) return res.sendStatus(404);
  return res.json(result);
});

const remove = catchError(async (req, res) => {
  const { id } = req.params;
  await User.destroy({ where: { id } });
  return res.sendStatus(204);
});

const update = catchError(async (req, res) => {
  const { id } = req.params;
  const { firtsName, lastName, country, image } = req.body;
  const result = await User.update(
    { firtsName, lastName, country, image },
    {
      where: { id },
      returning: true,
    }
  );
  if (result[0] === 0) return res.sendStatus(404);
  return res.json(result[1][0]);
});

const verifyCode = catchError(async (req, res) => {
  const { code } = req.params;
  const emailCode = await EmailCode.findOne({ where: { code } });
  if (!emailCode) return res.status(401).json({ message: "Invalid code" });
  const user = await User.findByPk(emailCode.userId);
  user.isVerified = true;
  await user.save();
  await emailCode.destroy();
  return res.json(user);
});

const login = catchError(async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ where: { email, isVerified: true } });
  if (!user) return res.status(401).json({ message: "Invalid credentiales" });

  const ifValid = await bcrypt.compare(password, user.password);
  if (!ifValid)
    return res.status(401).json({ message: "Invalid credentiales" });

  const token = jwt.sign(
    { user },
    process.env.TOKEN_SECRET,
    { expiresIn: '1d' }
  );

  return res.json({user, token});
});

const loggedUser = catchError(async (req, res) => {
  const  user  = req.user;
  return res.json(user);
});

const sendEmalToResetPassword = catchError(async (req, res) => {
  const { email, frontBaseUrl } = req.body;
  const user = await User.findOne({ where: { email }}); 
  if(!user) return res.status(401).json({message: "Invalid credentiales"})

  const code = require("crypto").randomBytes(20).toString("hex");
  const link = `${frontBaseUrl}/auth/reset_password/${code}`;

  await EmailCode.create({
    code,
    userId: user.id,
  });
  await sendEmail({
    to: email,
    subject: "Reset password for user app",
    html: ` <h1>Hello ${user.firstName} ${user.lastName}</h1>
            <p>Make sure to change your password, cliking on the link here:</p>
            <div>  <a href="${link}">${link}</a></div>
    `,
  })
  return res.status(201).json(user);
});

const resetPassword = catchError(async (req, res) => {
  const { code } = req.params;
  const { password } = req.body
  const emailCode = await EmailCode.findOne({ where: { code } });
  if (!emailCode) return res.status(401).json({ message: "Invalid code" });
  const encryptedPassword = await bcrypt.hash(password, 10);
  const user = await User.findByPk(emailCode.userId);
  user.password = encryptedPassword;
  await user.save();
  await emailCode.destroy();
  return res.json(user);
});

module.exports = {
  getAll,
  create,
  getOne,
  remove,
  update,
  verifyCode,
  login,
  loggedUser,
  sendEmalToResetPassword,
  resetPassword
};
