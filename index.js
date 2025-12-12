// =====================================================
// GLOM AUTHORIZATION SYSTEM - FINAL
// =====================================================

import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import speakeasy from "speakeasy";
import qrcode from "qrcode";
import axios from "axios";
import cors from "cors";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();
const app = express();

// ---------------- BASIC ----------------
app.use(express.json());
app.use(cors());
app.options("*", cors());

// ---------------- PATH ----------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------------- DATABASE ----------------
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
  discord: { id: String, username: String },
  totp: { enabled: { type: Boolean, default: false }, secret: String }
});
const User = mongoose.model("User", UserSchema);

const ProductSchema = new mongoose.Schema({
  name: String,
  authType: { type: String, enum: ["KEY", "USERPASS", "BOTH"] },
  apiPath: { type: String, unique: true },
  note: String,
  update: {
    latestVersion: String,
    downloadUrl: String,
    force: Boolean
  }
});
const Product = mongoose.model("Product", ProductSchema);

const LicenseSchema = new mongoose.Schema({
  product: { type: mongoose.Schema.Types.ObjectId, ref: "Product" },
  type: { type: String, enum: ["KEY", "USERPASS"] },
  key: String,
  username: String,
  password: String,
  hwid: String,
  status: { type: String, enum: ["ACTIVE", "DISABLED", "EXPIRED"], default: "ACTIVE" },
  expiresAt: Date,
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" }
});
const License = mongoose.model("License", LicenseSchema);

// =====================================================
// UTILS
// =====================================================
function auth(roles = []) {
  return (req, res, next) => {
    try {
      const token = req.headers.authorization?.split(" ")[1];
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      if (roles.length && !roles.includes(decoded.role)) return res.sendStatus(403);
      req.user = decoded;
      next();
    } catch {
      res.sendStatus(401);
    }
  };
}

const genKey = () => Math.random().toString(36).substring(2, 10).toUpperCase();
const genUser = () => "u_" + Math.random().toString(36).substring(2, 8);
const genPass = () => Math.random().toString(36).substring(2, 12);

// =====================================================
// SERVE PANEL
// =====================================================
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "theme.html"));
});

// =====================================================
// AUTH
// =====================================================
app.post("/auth/bootstrap", async (req, res) => {
  if (await User.findOne({ role: "MASTER" }))
    return res.status(403).json({ error: "Already initialized" });

  const hash = await bcrypt.hash(req.body.password, 10);
  await User.create({ username: req.body.username, password: hash, role: "MASTER" });
  res.json({ success: true });
});

app.post("/auth/login", async (req, res) => {
  const u = await User.findOne({ username: req.body.username });
  if (!u || !(await bcrypt.compare(req.body.password, u.password)))
    return res.status(401).json({ error: "Invalid credentials" });

  if (u.totp.enabled) {
    const ok = speakeasy.totp.verify({
      secret: u.totp.secret,
      encoding: "base32",
      token: req.body.totp
    });
    if (!ok) return res.status(401).json({ error: "Invalid 2FA" });
  }

  const token = jwt.sign(
    { id: u._id, role: u.role },
    process.env.JWT_SECRET,
    { expiresIn: "12h" }
  );

  res.json({ token });
});

// =====================================================
// DASHBOARD
// =====================================================
app.get("/dashboard/data", auth(), async (req, res) => {
  const user = await User.findById(req.user.id);
  const products = await Product.find();
  const licenses = await License.find({ createdBy: user._id }).populate("product");

  res.json({
    user: { username: user.username, role: user.role },
    products,
    licenses
  });
});

// =====================================================
// PRODUCTS
// =====================================================
app.post("/products/create", auth(["MASTER", "OWNER"]), async (req, res) => {
  res.json(await Product.create(req.body));
});

// =====================================================
// LICENSES
// =====================================================
app.post("/licenses/create", auth(["MASTER", "OWNER", "SOURCE"]), async (req, res) => {
  const l = await License.create({
    product: req.body.productId,
    type: req.body.type,
    key: req.body.type === "KEY" ? genKey() : undefined,
    username: req.body.type !== "KEY" ? genUser() : undefined,
    password: req.body.type !== "KEY" ? genPass() : undefined,
    createdBy: req.user.id
  });
  res.json(l);
});

// =====================================================
// LOADER API
// =====================================================
app.post("/glom/api/loader/:name", async (req, res) => {
  const product = await Product.findOne({ apiPath: `/glom/api/loader/${req.params.name}` });
  if (!product) return res.sendStatus(404);

  const lic = await License.findOne({ key: req.body.key, product: product._id });
  if (!lic || lic.status !== "ACTIVE") return res.sendStatus(403);

  if (!lic.hwid) {
    lic.hwid = req.body.hwid;
    await lic.save();
  } else if (lic.hwid !== req.body.hwid) {
    return res.status(403).json({ error: "HWID mismatch" });
  }

  res.json({ success: true });
});

// =====================================================
app.listen(process.env.PORT || 3000, () =>
  console.log("GLOM Authorization running")
);
