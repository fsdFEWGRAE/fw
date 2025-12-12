// =====================================================
// GLOM AUTHORIZATION SYSTEM - FINAL (WITH MASTER RESET)
// =====================================================

import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import speakeasy from "speakeasy";
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
  .catch(err => console.error("MongoDB Error:", err));

// =====================================================
// MODELS
// =====================================================
const UserSchema = new mongoose.Schema({
  username: String,
  password: String,
  role: { type: String, enum: ["MASTER", "OWNER", "SOURCE", "PANEL"] },
  totp: { enabled: { type: Boolean, default: false }, secret: String }
});
const User = mongoose.model("User", UserSchema);

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

// =====================================================
// SERVE PANEL
// =====================================================
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "theme.html"));
});

// =====================================================
// AUTH
// =====================================================

// BOOTSTRAP (مرة وحدة)
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

// LOGIN
app.post("/auth/login", async (req, res) => {
  const u = await User.findOne({ username: req.body.username });
  if (!u) return res.status(401).json({ error: "Invalid credentials" });

  const ok = await bcrypt.compare(req.body.password, u.password);
  if (!ok) return res.status(401).json({ error: "Invalid credentials" });

  if (u.totp.enabled) {
    const verified = speakeasy.totp.verify({
      secret: u.totp.secret,
      encoding: "base32",
      token: req.body.totp
    });
    if (!verified) return res.status(401).json({ error: "Invalid 2FA" });
  }

  const token = jwt.sign(
    { id: u._id, role: u.role },
    process.env.JWT_SECRET,
    { expiresIn: "12h" }
  );

  res.json({ token });
});

// =====================================================
// 🔐 FORCE RESET MASTER PASSWORD (الحل النهائي)
// =====================================================
app.post("/__debug/reset-master", async (req, res) => {
  const { secret, newPassword } = req.body;

  if (secret !== process.env.JWT_SECRET) {
    return res.status(403).json({ error: "Forbidden" });
  }

  const master = await User.findOne({ role: "MASTER" });
  if (!master) {
    return res.status(404).json({ error: "No MASTER found" });
  }

  master.password = await bcrypt.hash(newPassword, 10);
  await master.save();

  res.json({
    success: true,
    username: master.username
  });
});

// =====================================================
app.listen(process.env.PORT || 3000, () =>
  console.log("GLOM Authorization running")
);
