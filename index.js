// =====================================================
// GLOM AUTHORIZATION SYSTEM - CORE
// index.js
// =====================================================

import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import speakeasy from "speakeasy";
import qrcode from "qrcode";
import axios from "axios";
import dotenv from "dotenv";

dotenv.config();
const app = express();
app.use(express.json());

// =====================================================
// DATABASE
// =====================================================
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.error(err));

// =====================================================
// MODELS
// =====================================================
const UserSchema = new mongoose.Schema({
  username: String,
  password: String,
  role: { type: String, enum: ["MASTER", "OWNER", "SOURCE", "PANEL"] },
  discord: {
    id: String,
    username: String
  },
  totp: {
    enabled: { type: Boolean, default: false },
    secret: String
  }
});

const User = mongoose.model("User", UserSchema);

// =====================================================
// UTILS
// =====================================================
function auth(requiredRoles = []) {
  return (req, res, next) => {
    try {
      const token = req.headers.authorization?.split(" ")[1];
      if (!token) return res.status(401).json({ error: "No token" });

      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = decoded;

      if (requiredRoles.length && !requiredRoles.includes(decoded.role)) {
        return res.status(403).json({ error: "Forbidden" });
      }
      next();
    } catch {
      return res.status(401).json({ error: "Invalid token" });
    }
  };
}

// =====================================================
// AUTH ROUTES
// =====================================================

// Register (MASTER only – أول حساب)
app.post("/auth/bootstrap", async (req, res) => {
  const exists = await User.findOne({ role: "MASTER" });
  if (exists) return res.status(403).json({ error: "Already initialized" });

  const hash = await bcrypt.hash(req.body.password, 10);
  await User.create({
    username: req.body.username,
    password: hash,
    role: "MASTER"
  });

  res.json({ success: true });
});

// Login
app.post("/auth/login", async (req, res) => {
  const { username, password, totp } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ error: "Invalid credentials" });

  if (user.totp.enabled) {
    const verified = speakeasy.totp.verify({
      secret: user.totp.secret,
      encoding: "base32",
      token: totp
    });
    if (!verified) return res.status(401).json({ error: "Invalid 2FA" });
  }

  const token = jwt.sign(
    { id: user._id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "12h" }
  );

  res.json({ token });
});

// Enable TOTP
app.post("/auth/2fa/setup", auth(), async (req, res) => {
  const secret = speakeasy.generateSecret();
  await User.findByIdAndUpdate(req.user.id, {
    totp: { enabled: true, secret: secret.base32 }
  });

  const qr = await qrcode.toDataURL(secret.otpauth_url);
  res.json({ qr });
});

// Disable 2FA (MASTER only)
app.post("/auth/2fa/disable/:id", auth(["MASTER"]), async (req, res) => {
  await User.findByIdAndUpdate(req.params.id, {
    totp: { enabled: false, secret: null }
  });
  res.json({ success: true });
});

// =====================================================
// DISCORD OAUTH
// =====================================================
app.get("/auth/discord", (req, res) => {
  const redirect =
    `https://discord.com/oauth2/authorize?client_id=${process.env.DISCORD_CLIENT_ID}` +
    `&redirect_uri=${encodeURIComponent(process.env.DISCORD_REDIRECT)}` +
    `&response_type=code&scope=identify`;
  res.redirect(redirect);
});

app.get("/auth/discord/callback", async (req, res) => {
  const code = req.query.code;

  const tokenRes = await axios.post(
    "https://discord.com/api/oauth2/token",
    new URLSearchParams({
      client_id: process.env.DISCORD_CLIENT_ID,
      client_secret: process.env.DISCORD_CLIENT_SECRET,
      grant_type: "authorization_code",
      code,
      redirect_uri: process.env.DISCORD_REDIRECT
    }),
    { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
  );

  const userRes = await axios.get("https://discord.com/api/users/@me", {
    headers: { Authorization: `Bearer ${tokenRes.data.access_token}` }
  });

  await User.findByIdAndUpdate(req.query.state, {
    discord: {
      id: userRes.data.id,
      username: userRes.data.username
    }
  });

  res.send("Discord linked. You can close this.");
});

// =====================================================
app.listen(process.env.PORT || 3000, () =>
  console.log("GLOM Auth running")
);
// =====================================================
// MODELS – PRODUCTS & LICENSES
// =====================================================

const ProductSchema = new mongoose.Schema({
  name: { type: String, required: true },

  authType: {
    type: String,
    enum: ["KEY", "USERPASS", "BOTH"],
    required: true
  },

  apiPath: { type: String, unique: true }, // رابط المنتج

  note: String,

  allowedSources: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  allowedPanels: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],

  update: {
    latestVersion: String,
    downloadUrl: String,
    force: { type: Boolean, default: false }
  }
});

const Product = mongoose.model("Product", ProductSchema);

// -----------------------------------------------------

const LicenseSchema = new mongoose.Schema({
  product: { type: mongoose.Schema.Types.ObjectId, ref: "Product" },

  type: { type: String, enum: ["KEY", "USERPASS"] },

  key: String,
  username: String,
  password: String,

  hwid: String,
  hwidLocked: { type: Boolean, default: true },

  status: {
    type: String,
    enum: ["ACTIVE", "DISABLED", "EXPIRED"],
    default: "ACTIVE"
  },

  expiresAt: Date,
  createdAt: { type: Date, default: Date.now },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" }
});

const License = mongoose.model("License", LicenseSchema);

// =====================================================
// UTILS – GENERATE & DURATION
// =====================================================

function generateKey() {
  return [...Array(4)]
    .map(() => Math.random().toString(36).substring(2, 6).toUpperCase())
    .join("-");
}

function generateUsername() {
  return "u_" + Math.random().toString(36).substring(2, 10);
}

function generatePassword() {
  return Math.random().toString(36).substring(2, 14);
}

function calcExpiry(value, unit) {
  const now = new Date();

  switch (unit) {
    case "HOUR": now.setHours(now.getHours() + value); break;
    case "DAY": now.setDate(now.getDate() + value); break;
    case "MONTH": now.setMonth(now.getMonth() + value); break;
    case "YEAR": now.setFullYear(now.getFullYear() + value); break;
    default: return null;
  }

  return now;
}

// =====================================================
// PRODUCTS ROUTES
// =====================================================

// CREATE PRODUCT (MASTER / OWNER)
app.post("/products/create", auth(["MASTER", "OWNER"]), async (req, res) => {
  const product = await Product.create({
    name: req.body.name,
    authType: req.body.authType,
    apiPath: req.body.apiPath,
    note: req.body.note || ""
  });

  res.json(product);
});

// UPDATE PRODUCT UPDATE INFO
app.post("/products/update/:id", auth(["MASTER", "OWNER"]), async (req, res) => {
  await Product.findByIdAndUpdate(req.params.id, {
    update: req.body
  });

  res.json({ success: true });
});

// =====================================================
// LICENSE CRUD
// =====================================================

// CREATE LICENSE
app.post("/licenses/create", auth(["MASTER", "OWNER", "SOURCE"]), async (req, res) => {
  const {
    productId,
    type,
    durationValue,
    durationUnit,
    auto
  } = req.body;

  const product = await Product.findById(productId);
  if (!product) return res.status(404).json({ error: "Product not found" });

  if (req.user.role === "SOURCE") {
    if (!product.allowedSources.includes(req.user.id)) {
      return res.status(403).json({ error: "Not allowed" });
    }
  }

  const licenseData = {
    product: productId,
    type,
    expiresAt: calcExpiry(durationValue, durationUnit),
    createdBy: req.user.id
  };

  if (type === "KEY") {
    licenseData.key = auto ? generateKey() : req.body.key;
  } else {
    licenseData.username = auto ? generateUsername() : req.body.username;
    licenseData.password = auto ? generatePassword() : req.body.password;
  }

  const license = await License.create(licenseData);
  res.json(license);
});

// CHANGE LICENSE STATUS
app.post("/licenses/status/:id", auth(["MASTER", "OWNER", "SOURCE"]), async (req, res) => {
  await License.findByIdAndUpdate(req.params.id, {
    status: req.body.status
  });

  res.json({ success: true });
});

// EXTEND LICENSE
app.post("/licenses/extend/:id", auth(["MASTER", "OWNER"]), async (req, res) => {
  const lic = await License.findById(req.params.id);
  lic.expiresAt = calcExpiry(req.body.value, req.body.unit);
  await lic.save();

  res.json(lic);
});

// RESET HWID
app.post("/licenses/reset-hwid/:id", auth(["MASTER", "OWNER"]), async (req, res) => {
  await License.findByIdAndUpdate(req.params.id, { hwid: null });
  res.json({ success: true });
});

// =====================================================
// LOADER AUTH API (PER PRODUCT LINK)
// =====================================================

app.post("/glom/api/loader/:product", async (req, res) => {
  const product = await Product.findOne({
    apiPath: `/glom/api/loader/${req.params.product}`
  });

  if (!product) return res.status(404).json({ error: "Invalid product" });

  const { key, username, password, hwid, version } = req.body;
  let license;

  if (product.authType === "KEY") {
    license = await License.findOne({ key, product: product._id });
  } else {
    license = await License.findOne({
      username,
      password,
      product: product._id
    });
  }

  if (!license) return res.status(401).json({ error: "Invalid license" });
  if (license.status !== "ACTIVE")
    return res.status(403).json({ error: "License inactive" });

  if (license.expiresAt && license.expiresAt < new Date()) {
    license.status = "EXPIRED";
    await license.save();
    return res.status(403).json({ error: "Expired" });
  }

  // HWID BIND (FIRST USE)
  if (!license.hwid) {
    license.hwid = hwid;
    await license.save();
  } else if (license.hwid !== hwid) {
    return res.status(403).json({ error: "HWID mismatch" });
  }

  // UPDATE CHECK
  if (
    product.update?.force &&
    version !== product.update.latestVersion
  ) {
    return res.json({
      update: true,
      download: product.update.downloadUrl
    });
  }

  res.json({ success: true });
});
// =====================================================
// DASHBOARD DATA (ROLE BASED)
// =====================================================
app.get("/dashboard/data", auth(), async (req, res) => {
  const user = await User.findById(req.user.id);

  let products = [];
  let licenses = [];

  if (user.role === "MASTER" || user.role === "OWNER") {
    products = await Product.find();
    licenses = await License.find().populate("product");
  }

  if (user.role === "SOURCE") {
    products = await Product.find({ allowedSources: user._id });
    licenses = await License.find({ createdBy: user._id }).populate("product");
  }

  if (user.role === "PANEL") {
    licenses = await License.find({ createdBy: user._id }).populate("product");
  }

  res.json({
    user: {
      id: user._id,
      username: user.username,
      role: user.role,
      discord: user.discord,
      totp: user.totp.enabled
    },
    products,
    licenses
  });
});

// =====================================================
// UPDATE TOKEN SYSTEM (SECURE DOWNLOAD)
// =====================================================
app.post("/glom/api/update-token", async (req, res) => {
  const { productId } = req.body;

  const token = jwt.sign(
    { productId },
    process.env.JWT_SECRET,
    { expiresIn: "5m" }
  );

  res.json({ token });
});

app.get("/glom/api/download/:token", async (req, res) => {
  try {
    const decoded = jwt.verify(req.params.token, process.env.JWT_SECRET);
    const product = await Product.findById(decoded.productId);
    if (!product || !product.update?.downloadUrl) {
      return res.sendStatus(403);
    }

    res.redirect(product.update.downloadUrl);
  } catch {
    res.sendStatus(403);
  }
});

// =====================================================
// USER MANAGEMENT (MASTER / OWNER)
// =====================================================
app.post("/users/create", auth(["MASTER", "OWNER"]), async (req, res) => {
  const { username, password, role } = req.body;

  if (role === "MASTER" && req.user.role !== "MASTER") {
    return res.status(403).json({ error: "Only MASTER can create MASTER" });
  }

  if (role === "OWNER" && req.user.role !== "MASTER") {
    return res.status(403).json({ error: "Only MASTER can create OWNER" });
  }

  const hash = await bcrypt.hash(password, 10);

  const user = await User.create({
    username,
    password: hash,
    role
  });

  res.json(user);
});
