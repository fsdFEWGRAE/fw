import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import bodyParser from "body-parser";
import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import speakeasy from "speakeasy";
import qrcode from "qrcode";
import fetch from "node-fetch";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// =========================
// MIDDLEWARE
// =========================
app.use(cors());
app.use(bodyParser.json());

// =========================
// DB CONNECT
// =========================
const mongoUri = process.env.MONGO_URI || "";
if (!mongoUri) {
  console.warn("WARNING: MONGO_URI is empty. Set it in Render Dashboard.");
}

mongoose
  .connect(mongoUri)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err.message);
    process.exit(1);
  });

// =========================
// MODELS
// =========================
const userSchema = new mongoose.Schema(
  {
    username: String,
    password: String,
    roleCode: { type: String, default: "PANEL" }, // MASTER / OWNER / SOURCE / PANEL
    twoFAEnabled: { type: Boolean, default: false },
    twoFASecret: { type: String, default: null },
    discordId: { type: String, default: null },
    lastLoginAt: { type: Date, default: null }
  },
  { timestamps: true }
);

const roleSchema = new mongoose.Schema({
  name: String,
  code: String,
  level: Number
});

const productSchema = new mongoose.Schema(
  {
    name: String,
    description: String
  },
  { timestamps: true }
);

const sessionSchema = new mongoose.Schema(
  {
    userId: String,
    token: String,
    ip: String,
    userAgent: String,
    expiresAt: Date
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);
const Role = mongoose.model("Role", roleSchema);
const Product = mongoose.model("Product", productSchema);
const Session = mongoose.model("Session", sessionSchema);

// =========================
// DEFAULT ROLES + MASTER
// =========================
async function ensureDefaults() {
  const roleCount = await Role.countDocuments();
  if (roleCount === 0) {
    await Role.insertMany([
      { name: "Master Source", code: "MASTER", level: 999 },
      { name: "OWN Source", code: "OWNER", level: 700 },
      { name: "Source", code: "SOURCE", level: 400 },
      { name: "Panel", code: "PANEL", level: 100 }
    ]);
    console.log("🔥 Default roles created");
  }

  const masterExists = await User.findOne({ roleCode: "MASTER" });
  if (!masterExists) {
    await User.create({
      username: "admin",
      password: "admin123", // غيّره من .env لما تحب
      roleCode: "MASTER"
    });
    console.log("👑 MASTER user created: admin / admin123");
  }
}
ensureDefaults().catch(console.error);

// =========================
// HELPERS
// =========================
function getClientIp(req) {
  const hdr = req.headers["x-forwarded-for"];
  if (hdr) return hdr.split(",")[0].trim();
  return req.socket?.remoteAddress || "unknown";
}

function signToken(payload) {
  const secret = process.env.JWT_SECRET || "CHANGE_THIS_SECRET";
  return jwt.sign(payload, secret, { expiresIn: "1d" });
}

function verifyToken(token) {
  const secret = process.env.JWT_SECRET || "CHANGE_THIS_SECRET";
  return jwt.verify(token, secret);
}

// =========================
// AUTH MIDDLEWARE
// =========================
async function authCheck(req, res, next) {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
    if (!token) {
      return res
        .status(401)
        .json({ success: false, message: "Unauthorized (no token)" });
    }

    const decoded = verifyToken(token);
    const session = await Session.findOne({ token });
    if (!session) {
      return res
        .status(401)
        .json({ success: false, message: "Unauthorized (session not found)" });
    }

    req.user = {
      userId: decoded.userId,
      roleCode: decoded.roleCode,
      token
    };

    next();
  } catch (err) {
    return res
      .status(401)
      .json({ success: false, message: "Unauthorized (invalid token)" });
  }
}

function requireRoles(rolesArray) {
  return (req, res, next) => {
    if (!req.user || !rolesArray.includes(req.user.roleCode)) {
      return res
        .status(403)
        .json({ success: false, message: "403 — You Do Not Have Permission" });
    }
    next();
  };
}

// =========================
// BASE ROUTER
// =========================
const api = express.Router();
app.use("/glom/api", api);

// =========================
// AUTH: /auth/login
// =========================
api.post("/auth/login", async (req, res) => {
  try {
    const { username, password, code } = req.body || {};
    if (!username || !password) {
      return res.json({
        success: false,
        message: "Username and password are required"
      });
    }

    const user = await User.findOne({ username });
    if (!user || user.password !== password) {
      return res.json({ success: false, message: "Invalid credentials" });
    }

    // 2FA check (if enabled)
    if (user.twoFAEnabled) {
      if (!code) {
        return res.json({
          success: false,
          message: "2FA code required"
        });
      }
      const ok = speakeasy.totp.verify({
        secret: user.twoFASecret,
        encoding: "base32",
        token: code,
        window: 1
      });
      if (!ok) {
        return res.json({ success: false, message: "Invalid 2FA code" });
      }
    }

    // create JWT + Session
    const payload = { userId: user._id.toString(), roleCode: user.roleCode };
    const token = signToken(payload);

    const ip = getClientIp(req);
    const userAgent = req.headers["user-agent"] || "Unknown";
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

    await Session.create({
      userId: user._id.toString(),
      token,
      ip,
      userAgent,
      expiresAt
    });

    user.lastLoginAt = new Date();
    await user.save();

    return res.json({
      success: true,
      token,
      user: {
        id: user._id.toString(),
        username: user.username,
        roleCode: user.roleCode,
        twoFAEnabled: user.twoFAEnabled,
        discordLinked: !!user.discordId
      }
    });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

// =========================
// USERS (ADMIN VIEW)
// =========================
api.get(
  "/users/all",
  authCheck,
  requireRoles(["MASTER", "OWNER"]),
  async (req, res) => {
    const users = await User.find().select("-password -twoFASecret");
    return res.json({ success: true, users });
  }
);

// =========================
// PRODUCTS
// =========================
api.post(
  "/products/create",
  authCheck,
  requireRoles(["MASTER", "OWNER"]),
  async (req, res) => {
    const { name, description } = req.body || {};
    if (!name) {
      return res.json({ success: false, message: "Name is required" });
    }
    const exists = await Product.findOne({ name });
    if (exists) {
      return res.json({ success: false, message: "Product already exists" });
    }
    await Product.create({ name, description: description || "" });
    return res.json({ success: true, message: "Product created" });
  }
);

api.get("/products/all", authCheck, async (req, res) => {
  const products = await Product.find();
  return res.json({ success: true, products });
});

// =========================
// SECURITY PROFILE / 2FA / SESSIONS
// =========================
api.get("/security/profile", authCheck, async (req, res) => {
  const user = await User.findById(req.user.userId);
  if (!user) {
    return res.status(404).json({ success: false, message: "User not found" });
  }
  return res.json({
    success: true,
    twoFAEnabled: !!user.twoFAEnabled,
    discordLinked: !!user.discordId
  });
});

api.post("/security/2fa/setup", authCheck, async (req, res) => {
  const user = await User.findById(req.user.userId);
  if (!user) {
    return res.status(404).json({ success: false, message: "User not found" });
  }
  const secret = speakeasy.generateSecret({
    name: `GLOM Authorization (${user.username})`
  });
  user.twoFASecret = secret.base32;
  await user.save();

  qrcode.toDataURL(secret.otpauth_url, (err, dataUrl) => {
    if (err) {
      console.error(err);
      return res
        .status(500)
        .json({ success: false, message: "QR generation failed" });
    }
    return res.json({ success: true, qr: dataUrl });
  });
});

api.post("/security/2fa/verify", authCheck, async (req, res) => {
  const { code } = req.body || {};
  const user = await User.findById(req.user.userId);
  if (!user || !user.twoFASecret) {
    return res.json({
      success: false,
      message: "2FA is not initialized for this user"
    });
  }
  const ok = speakeasy.totp.verify({
    secret: user.twoFASecret,
    encoding: "base32",
    token: code,
    window: 1
  });
  if (!ok) {
    return res.json({ success: false, message: "Invalid Code" });
  }
  user.twoFAEnabled = true;
  await user.save();
  return res.json({ success: true, message: "2FA Enabled" });
});

api.post("/security/2fa/disable", authCheck, async (req, res) => {
  const user = await User.findById(req.user.userId);
  if (!user) {
    return res.status(404).json({ success: false, message: "User not found" });
  }
  user.twoFAEnabled = false;
  user.twoFASecret = null;
  await user.save();
  return res.json({ success: true, message: "2FA Disabled" });
});

// SESSIONS
api.get("/security/sessions", authCheck, async (req, res) => {
  const sessions = await Session.find({ userId: req.user.userId });
  return res.json({ success: true, sessions });
});

api.delete("/security/sessions/:id", authCheck, async (req, res) => {
  await Session.deleteOne({ _id: req.params.id, userId: req.user.userId });
  return res.json({ success: true });
});

api.delete("/security/sessions", authCheck, async (req, res) => {
  await Session.deleteMany({ userId: req.user.userId });
  return res.json({ success: true });
});

// =========================
// DISCORD LINKING
// =========================
api.get("/security/discord/login", authCheck, async (req, res) => {
  try {
    const clientId = process.env.DISCORD_CLIENT_ID;
    const redirectUri = process.env.DISCORD_REDIRECT_URI;
    if (!clientId || !redirectUri) {
      return res.status(500).send("Discord env not configured");
    }

    const state = signToken({ userId: req.user.userId });
    const encodedRedirect = encodeURIComponent(redirectUri);

    const url = `https://discord.com/oauth2/authorize?client_id=${clientId}&response_type=code&scope=identify&redirect_uri=${encodedRedirect}&state=${state}`;
    return res.redirect(url);
  } catch (err) {
    console.error(err);
    return res.status(500).send("Discord login error");
  }
});

api.get("/security/discord/callback", async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || !state) {
      return res.status(400).send("Missing code or state");
    }

    let decoded;
    try {
      decoded = verifyToken(state);
    } catch {
      return res.status(400).send("Invalid state");
    }

    const clientId = process.env.DISCORD_CLIENT_ID;
    const clientSecret = process.env.DISCORD_CLIENT_SECRET;
    const redirectUri = process.env.DISCORD_REDIRECT_URI;
    if (!clientId || !clientSecret || !redirectUri) {
      return res.status(500).send("Discord env not configured");
    }

    // Exchange code for token
    const tokenResp = await fetch("https://discord.com/api/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret,
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri
      })
    });

    if (!tokenResp.ok) {
      const txt = await tokenResp.text();
      console.error("Discord token error:", txt);
      return res.status(500).send("Discord token exchange failed");
    }

    const tokenJson = await tokenResp.json();
    const accessToken = tokenJson.access_token;

    // Get user
    const userResp = await fetch("https://discord.com/api/users/@me", {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    const discordProfile = await userResp.json();

    const userId = decoded.userId;
    const user = await User.findById(userId);
    if (!user) return res.status(404).send("User not found");

    user.discordId = discordProfile.id;
    await user.save();

    return res.send("✅ Your Discord account is now linked. You can close this page.");
  } catch (err) {
    console.error("Discord callback error:", err);
    return res.status(500).send("Discord callback error");
  }
});

// =========================
// THEME / FRONTEND (theme.html)
// =========================
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "theme.html"));
});

// نفس الصفحة لكل مسارات البانل
app.get(["/dashboard", "/auth/login", "/security", "/products"], (req, res) => {
  res.sendFile(path.join(__dirname, "theme.html"));
});

// catch-all → panel (يمكن تعديله لاحقًا)
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "theme.html"));
});

// =========================
// START
// =========================
app.listen(PORT, () => {
  console.log(`🚀 GLOM Authorization running on port ${PORT}`);
});
