// ===============================================
// GLOM AUTHORIZATION SYSTEM — SINGLE FILE BACKEND
// MODE: MASTER / OWNER / SOURCE / PANEL
// PRODUCTS — KEYS — LOADER — API PROXY — 2FA — DISCORD
// PATH: /glom/api
// PORT: 3000
// ===============================================

import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import useragent from "express-useragent";
import geoip from "geoip-lite";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

// ======================= CONFIG ==========================
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "GLOM_AUTH_SECRET_2025";
const MONGO_URI = process.env.MONGO_URI || "PASTE_MONGO_ATLAS_URI";

// ======================= EXPRESS INIT =====================
const app = express();
app.use(cors());
app.use(express.json());
app.use(useragent.express());

// ======================= STATIC THEME =====================
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// الصفحة الرئيسية: الثيم
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "theme.html"));
});

// ======================= DATABASE =========================
mongoose.set("strictQuery", false);

mongoose
  .connect(MONGO_URI)
  .then(() => console.log("Mongo Connected ✔"))
  .catch((err) => console.error("DB ERROR ❌", err));

// ======================= SCHEMAS ==========================

// USERS
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  role: String, // MASTER / OWNER / SOURCE / PANEL
  parent: String, // OWNER→MASTER | SOURCE→OWNER | PANEL→SOURCE
  twoFA: {
    enabled: { type: Boolean, default: false },
    secret: String,
  },
  discord: {
    linked: { type: Boolean, default: false },
    id: String,
    name: String,
  },
});

// PRODUCTS
const productSchema = new mongoose.Schema({
  name: String,
  owner: String, // MASTER or OWNER
  loginMode: String, // USER_PASS | KEY | BOTH
  apiToken: String, // custom per product for loader
  allowedSources: [String], // usernames of SOURCE allowed to resell
  allowedPanels: [String], // usernames of PANEL allowed to use
  loaderLoginNote: String, // optional text for loader login
});

// KEYS
const keySchema = new mongoose.Schema({
  productId: String,
  key: String,
  assignedUser: String,
  expires: Date,
});

// LOADER UPDATES
const updateSchema = new mongoose.Schema({
  productId: String,
  version: String,
  gofileContentId: String, // direct or normal gofile link
  note: String,
  uploadedBy: String,
  date: { type: Date, default: Date.now },
});

// SESSIONS (ADVANCED)
const sessionSchema = new mongoose.Schema({
  userId: String,
  username: String,
  ip: String,
  device: String,
  os: String,
  browser: String,
  country: String,
  city: String,
  loginTime: { type: Date, default: Date.now },
});

const User = mongoose.model("users", userSchema);
const Product = mongoose.model("products", productSchema);
const Key = mongoose.model("keys", keySchema);
const Update = mongoose.model("loaderupdates", updateSchema);
const Session = mongoose.model("sessions", sessionSchema);

// ======================= AUTO CREATE MASTER ==========================
async function autoCreateMaster() {
  try {
    const exist = await User.findOne({ role: "MASTER" });
    if (!exist) {
      const hashed = await bcrypt.hash("JustSpecter0", 10);
      await User.create({
        username: "RAXX",
        password: hashed,
        role: "MASTER",
      });
      console.log(
        "MASTER AUTO CREATED ✔ Username: RAXX | Pass: JustSpecter0"
      );
    }
  } catch (e) {
    console.error("AUTO MASTER ERROR", e);
  }
}
autoCreateMaster();

// ======================= JWT VERIFY MIDDLEWARE =======================
function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token)
    return res
      .status(401)
      .json({ success: false, message: "Unauthorized" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res
      .status(401)
      .json({ success: false, message: "Invalid Token" });
  }
}

// ======================= ROLE VALIDATION ==============================
function allowRoles(...allowed) {
  return (req, res, next) => {
    if (!req.user || !allowed.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: "403 — You Do Not Have Permission",
      });
    }
    next();
  };
}

// ======================= SESSION TRACK ===============================
async function trackSession(req, userid, username) {
  try {
    const ip =
      req.headers["x-forwarded-for"] ||
      req.socket.remoteAddress ||
      "Unknown";
    const geo = geoip.lookup(ip) || {};

    await Session.create({
      userId: userid,
      username,
      ip,
      device: req.useragent.platform,
      os: req.useragent.os,
      browser: req.useragent.browser,
      country: geo.country || "N/A",
      city: geo.city || "N/A",
    });
  } catch (e) {
    console.error("SESSION TRACK ERROR", e);
  }
}

// ======================= HELPER: RANDOM KEY ===========================
function randomKey(len = 32) {
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let r = "";
  for (let i = 0; i < len; i++)
    r += chars[Math.floor(Math.random() * chars.length)];
  return r;
}

// ======================= AUTH ROUTES ==================================

// LOGIN (Username + Password only)
app.post("/glom/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password)
      return res
        .status(400)
        .json({ success: false, message: "Missing credentials" });

    const user = await User.findOne({ username });
    if (!user)
      return res
        .status(401)
        .json({ success: false, message: "Invalid login" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok)
      return res
        .status(401)
        .json({ success: false, message: "Invalid login" });

    // Create JWT
    const token = jwt.sign(
      {
        id: user._id.toString(),
        username: user.username,
        role: user.role,
      },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    // Track session ADVANCED
    await trackSession(req, user._id.toString(), user.username);

    return res.json({
      success: true,
      token,
      user: {
        id: user._id,
        username: user.username,
        role: user.role,
      },
    });
  } catch (e) {
    console.error("LOGIN ERROR", e);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// GET CURRENT USER
app.get("/glom/api/auth/me", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).lean();
    if (!user)
      return res
        .status(404)
        .json({ success: false, message: "User not found" });

    res.json({
      success: true,
      user: {
        id: user._id,
        username: user.username,
        role: user.role,
        twoFA: user.twoFA?.enabled || false,
        discordLinked: user.discord?.linked || false,
      },
    });
  } catch (e) {
    console.error("ME ERROR", e);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ======================= PRODUCT ROUTES ===============================

// CREATE PRODUCT (MASTER + OWNER)
// loginMode: "USER_PASS" | "KEY" | "BOTH"
app.post(
  "/glom/api/products/create",
  auth,
  allowRoles("MASTER", "OWNER"),
  async (req, res) => {
    try {
      let { name, loginMode, apiToken, loaderLoginNote } = req.body;
      if (!name || !loginMode)
        return res
          .status(400)
          .json({ success: false, message: "Missing fields" });

      if (!["USER_PASS", "KEY", "BOTH"].includes(loginMode))
        return res
          .status(400)
          .json({ success: false, message: "Invalid login mode" });

      if (!apiToken || !apiToken.trim()) {
        apiToken = "GLOM_" + randomKey(16);
      }

      const existing = await Product.findOne({ apiToken });
      if (existing)
        return res.status(400).json({
          success: false,
          message: "API token already used",
        });

      const doc = await Product.create({
        name,
        owner: req.user.username,
        loginMode,
        apiToken,
        allowedSources: [],
        allowedPanels: [],
        loaderLoginNote: loaderLoginNote || "",
      });

      res.json({ success: true, product: doc });
    } catch (e) {
      console.error("PRODUCT CREATE", e);
      res.status(500).json({ success: false, message: "Server error" });
    }
  }
);

// LIST PRODUCTS (filtered by role)
app.get("/glom/api/products/list", auth, async (req, res) => {
  try {
    let products;
    const user = await User.findById(req.user.id).lean();
    if (!user)
      return res
        .status(404)
        .json({ success: false, message: "User not found" });

    if (user.role === "MASTER") {
      products = await Product.find({}).lean();
    } else if (user.role === "OWNER") {
      products = await Product.find({ owner: user.username }).lean();
    } else if (user.role === "SOURCE") {
      products = await Product.find({
        allowedSources: user.username,
      }).lean();
    } else if (user.role === "PANEL") {
      products = await Product.find({
        allowedPanels: user.username,
      }).lean();
    } else {
      return res
        .status(403)
        .json({ success: false, message: "403 — Role not supported" });
    }

    res.json({ success: true, products });
  } catch (e) {
    console.error("PRODUCT LIST", e);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// UPDATE PRODUCT (MASTER + OWNER)
app.post(
  "/glom/api/products/update",
  auth,
  allowRoles("MASTER", "OWNER"),
  async (req, res) => {
    try {
      const { productId, name, loginMode, apiToken, loaderLoginNote } =
        req.body;
      if (!productId)
        return res
          .status(400)
          .json({ success: false, message: "Missing productId" });

      const prod = await Product.findById(productId);
      if (!prod)
        return res
          .status(404)
          .json({ success: false, message: "Product not found" });

      if (req.user.role === "OWNER" && prod.owner !== req.user.username)
        return res
          .status(403)
          .json({ success: false, message: "Not your product" });

      if (name) prod.name = name;
      if (loginMode && ["USER_PASS", "KEY", "BOTH"].includes(loginMode))
        prod.loginMode = loginMode;
      if (typeof loaderLoginNote === "string")
        prod.loaderLoginNote = loaderLoginNote;
      if (apiToken && apiToken.trim()) {
        const existToken = await Product.findOne({
          apiToken,
          _id: { $ne: productId },
        });
        if (existToken)
          return res.status(400).json({
            success: false,
            message: "API token already used",
          });
        prod.apiToken = apiToken;
      }

      await prod.save();
      res.json({ success: true, product: prod });
    } catch (e) {
      console.error("PRODUCT UPDATE", e);
      res.status(500).json({ success: false, message: "Server error" });
    }
  }
);

// DELETE PRODUCT (MASTER + OWNER)
app.post(
  "/glom/api/products/delete",
  auth,
  allowRoles("MASTER", "OWNER"),
  async (req, res) => {
    try {
      const { productId } = req.body;
      if (!productId)
        return res
          .status(400)
          .json({ success: false, message: "Missing productId" });

      const prod = await Product.findById(productId);
      if (!prod)
        return res
          .status(404)
          .json({ success: false, message: "Product not found" });

      if (req.user.role === "OWNER" && prod.owner !== req.user.username)
        return res
          .status(403)
          .json({ success: false, message: "Not your product" });

      await Product.deleteOne({ _id: productId });
      await Key.deleteMany({ productId });
      await Update.deleteMany({ productId });

      res.json({
        success: true,
        message: "Product & related data deleted",
      });
    } catch (e) {
      console.error("PRODUCT DELETE", e);
      res.status(500).json({ success: false, message: "Server error" });
    }
  }
);

// REGENERATE API TOKEN (MASTER + OWNER)
app.post(
  "/glom/api/products/regenerate-api",
  auth,
  allowRoles("MASTER", "OWNER"),
  async (req, res) => {
    try {
      const { productId } = req.body;
      if (!productId)
        return res
          .status(400)
          .json({ success: false, message: "Missing productId" });

      const prod = await Product.findById(productId);
      if (!prod)
        return res
          .status(404)
          .json({ success: false, message: "Product not found" });

      if (req.user.role === "OWNER" && prod.owner !== req.user.username)
        return res
          .status(403)
          .json({ success: false, message: "Not your product" });

      const newToken = "GLOM_" + randomKey(20);
      prod.apiToken = newToken;
      await prod.save();

      res.json({
        success: true,
        message: "API token regenerated",
        apiToken: newToken,
      });
    } catch (e) {
      console.error("REGENERATE API", e);
      res.status(500).json({ success: false, message: "Server error" });
    }
  }
);

// ======================= PRODUCT ASSIGNMENT ===========================

// MASTER / OWNER → assign product to SOURCE
app.post(
  "/glom/api/products/assign-source",
  auth,
  allowRoles("MASTER", "OWNER"),
  async (req, res) => {
    try {
      const { productId, sourceUsername } = req.body;
      if (!productId || !sourceUsername)
        return res
          .status(400)
          .json({ success: false, message: "Missing fields" });

      const prod = await Product.findById(productId);
      if (!prod)
        return res
          .status(404)
          .json({ success: false, message: "Product not found" });

      if (req.user.role === "OWNER" && prod.owner !== req.user.username)
        return res
          .status(403)
          .json({ success: false, message: "Not your product" });

      const srcUser = await User.findOne({
        username: sourceUsername,
        role: "SOURCE",
      });
      if (!srcUser)
        return res
          .status(404)
          .json({ success: false, message: "Source not found" });

      if (!prod.allowedSources.includes(sourceUsername))
        prod.allowedSources.push(sourceUsername);

      await prod.save();
      res.json({ success: true, product: prod });
    } catch (e) {
      console.error("ASSIGN SOURCE", e);
      res.status(500).json({ success: false, message: "Server error" });
    }
  }
);

// SOURCE (أو MASTER/OWNER) → assign product to PANEL
app.post(
  "/glom/api/products/assign-panel",
  auth,
  allowRoles("MASTER", "OWNER", "SOURCE"),
  async (req, res) => {
    try {
      const { productId, panelUsername } = req.body;
      if (!productId || !panelUsername)
        return res
          .status(400)
          .json({ success: false, message: "Missing fields" });

      const prod = await Product.findById(productId);
      if (!prod)
        return res
          .status(404)
          .json({ success: false, message: "Product not found" });

      // If SOURCE, must have permission for that product
      if (
        req.user.role === "SOURCE" &&
        !prod.allowedSources.includes(req.user.username)
      )
        return res.status(403).json({
          success: false,
          message: "You don't have this product",
        });

      const pnl = await User.findOne({
        username: panelUsername,
        role: "PANEL",
      });
      if (!pnl)
        return res
          .status(404)
          .json({ success: false, message: "Panel not found" });

      if (!prod.allowedPanels.includes(panelUsername))
        prod.allowedPanels.push(panelUsername);

      await prod.save();
      res.json({ success: true, product: prod });
    } catch (e) {
      console.error("ASSIGN PANEL", e);
      res.status(500).json({ success: false, message: "Server error" });
    }
  }
);

// ======================= KEYS ========================================

// CREATE KEY (MASTER + OWNER + SOURCE)
app.post(
  "/glom/api/keys/create",
  auth,
  allowRoles("MASTER", "OWNER", "SOURCE"),
  async (req, res) => {
    try {
      const { productId, panelUsername, days } = req.body;
      if (!productId || !panelUsername)
        return res
          .status(400)
          .json({ success: false, message: "Missing fields" });

      const prod = await Product.findById(productId);
      if (!prod)
        return res
          .status(404)
          .json({ success: false, message: "Product not found" });

      // Permission checks
      if (req.user.role === "OWNER" && prod.owner !== req.user.username)
        return res
          .status(403)
          .json({ success: false, message: "Not your product" });

      if (
        req.user.role === "SOURCE" &&
        !prod.allowedSources.includes(req.user.username)
      )
        return res.status(403).json({
          success: false,
          message: "You don't have this product",
        });

      if (!prod.allowedPanels.includes(panelUsername))
        return res.status(403).json({
          success: false,
          message: "Panel not assigned for this product",
        });

      const pnl = await User.findOne({
        username: panelUsername,
        role: "PANEL",
      });
      if (!pnl)
        return res.status(404).json({
          success: false,
          message: "Panel user not found",
        });

      // KEY generation
      const keyValue = randomKey(40);

      let expires = null;
      if (days && Number(days) > 0) {
        const now = Date.now();
        expires = new Date(now + Number(days) * 86400000);
      }

      const doc = await Key.create({
        productId,
        key: keyValue,
        assignedUser: panelUsername,
        expires,
      });

      res.json({
        success: true,
        key: {
          id: doc._id,
          value: keyValue,
          expires,
        },
      });
    } catch (e) {
      console.error("KEY CREATE", e);
      res.status(500).json({ success: false, message: "Server error" });
    }
  }
);

// LIST KEYS
app.get("/glom/api/keys/list", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).lean();
    if (!user)
      return res
        .status(404)
        .json({ success: false, message: "User not found" });

    let keys;
    if (user.role === "MASTER") {
      keys = await Key.find({}).lean();
    } else if (user.role === "OWNER") {
      const myProducts = await Product.find({
        owner: user.username,
      }).lean();
      const ids = myProducts.map((p) => p._id.toString());
      keys = await Key.find({ productId: { $in: ids } }).lean();
    } else if (user.role === "SOURCE") {
      const myProducts = await Product.find({
        allowedSources: user.username,
      }).lean();
      const ids = myProducts.map((p) => p._id.toString());
      keys = await Key.find({ productId: { $in: ids } }).lean();
    } else if (user.role === "PANEL") {
      keys = await Key.find({ assignedUser: user.username }).lean();
    } else {
      return res
        .status(403)
        .json({ success: false, message: "Role not supported" });
    }

    res.json({ success: true, keys });
  } catch (e) {
    console.error("KEY LIST", e);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ======================= LOADER CHECK + UPDATE PROXY ==================

// CHECK: loader auth + forced update system
// BODY: { apiToken, key, hwid, version }
app.post("/glom/api/loader/check", async (req, res) => {
  try {
    const { apiToken, key, hwid, version } = req.body;
    if (!apiToken || !key || !hwid || !version)
      return res
        .status(400)
        .json({ success: false, message: "Missing fields" });

    const prod = await Product.findOne({ apiToken });
    if (!prod)
      return res.json({
        success: false,
        status: "invalid_api",
        message: "Invalid API token",
      });

    const now = new Date();
    const licence = await Key.findOne({
      productId: prod._id.toString(),
      key,
    });
    if (!licence)
      return res.json({
        success: false,
        status: "no_key",
        message: "Key not found",
      });

    if (licence.expires && licence.expires < now)
      return res.json({
        success: false,
        status: "expired",
        message: "Key expired",
      });

    // check update
    const upd = await Update.findOne({
      productId: prod._id.toString(),
    }).lean();

    if (upd && upd.version && upd.version !== version) {
      const updateToken = jwt.sign(
        {
          productId: prod._id.toString(),
          key,
          hwid,
          version: upd.version,
        },
        JWT_SECRET,
        { expiresIn: "10m" }
      );

      return res.json({
        success: false,
        status: "update_required",
        forceUpdate: true,
        updateToken,
        newVersion: upd.version,
        note: upd.note || "",
      });
    }

    return res.json({ success: true, status: "ok" });
  } catch (e) {
    console.error("LOADER CHECK", e);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// PUSH UPDATE
// BODY: { productId, version, gofileUrl, note }
app.post(
  "/glom/api/loader/push-update",
  auth,
  allowRoles("MASTER", "OWNER"),
  async (req, res) => {
    try {
      const { productId, version, gofileUrl, note } = req.body;
      if (!productId || !version || !gofileUrl)
        return res
          .status(400)
          .json({ success: false, message: "Missing fields" });

      const prod = await Product.findById(productId);
      if (!prod)
        return res
          .status(404)
          .json({ success: false, message: "Product not found" });

      if (req.user.role === "OWNER" && prod.owner !== req.user.username)
        return res
          .status(403)
          .json({ success: false, message: "Not your product" });

      // replace old updates
      await Update.deleteMany({ productId });

      const doc = await Update.create({
        productId,
        version,
        gofileContentId: gofileUrl,
        note: note || "",
        uploadedBy: req.user.username,
      });

      res.json({ success: true, update: doc });
    } catch (e) {
      console.error("PUSH UPDATE", e);
      res.status(500).json({ success: false, message: "Server error" });
    }
  }
);

// LOADER UPDATE PROXY
// GET /glom/api/loader/update?token=...
app.get("/glom/api/loader/update", async (req, res) => {
  try {
    const { token } = req.query;
    if (!token)
      return res
        .status(400)
        .json({ success: false, message: "Missing token" });

    let payload;
    try {
      payload = jwt.verify(token, JWT_SECRET);
    } catch {
      return res
        .status(401)
        .json({ success: false, message: "Invalid update token" });
    }

    const upd = await Update.findOne({
      productId: payload.productId,
    }).lean();
    if (!upd || !upd.gofileContentId)
      return res
        .status(404)
        .json({ success: false, message: "No update found" });

    const url = upd.gofileContentId;

    const r = await fetch(url);
    if (!r.ok) {
      return res.status(500).json({
        success: false,
        message: "Failed to fetch file from gofile",
      });
    }

    res.setHeader("Content-Type", "application/octet-stream");
    res.setHeader(
      "Content-Disposition",
      'attachment; filename="glom_loader.bin"'
    );

    const buf = Buffer.from(await r.arrayBuffer());
    return res.end(buf);
  } catch (e) {
    console.error("LOADER UPDATE PROXY", e);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ======================= RESELLER USERS (OWNER / SOURCE / PANEL) ======

// Create user with specific role
app.post(
  "/glom/api/users/create",
  auth,
  allowRoles("MASTER", "OWNER", "SOURCE"),
  async (req, res) => {
    try {
      const { username, password, role } = req.body;
      if (!username || !password || !role)
        return res
          .status(400)
          .json({ success: false, message: "Missing fields" });

      if (!["OWNER", "SOURCE", "PANEL"].includes(role))
        return res
          .status(400)
          .json({ success: false, message: "Invalid role" });

      if (req.user.role === "OWNER" && role === "OWNER")
        return res.status(403).json({
          success: false,
          message: "OWNER cannot create another OWNER",
        });

      if (req.user.role === "SOURCE" && role !== "PANEL")
        return res.status(403).json({
          success: false,
          message: "SOURCE can only create PANEL",
        });

      const exists = await User.findOne({ username });
      if (exists)
        return res.status(400).json({
          success: false,
          message: "Username already used",
        });

      const hashed = await bcrypt.hash(password, 10);

      let parent = "MASTER";
      if (req.user.role === "OWNER") parent = req.user.username;
      if (req.user.role === "SOURCE") parent = req.user.username;

      const doc = await User.create({
        username,
        password: hashed,
        role,
        parent,
        twoFA: { enabled: false, secret: "" },
        discord: { linked: false, id: "", name: "" },
      });

      res.json({
        success: true,
        user: {
          id: doc._id,
          username: doc.username,
          role: doc.role,
          parent: doc.parent,
        },
      });
    } catch (e) {
      console.error("USER CREATE", e);
      res.status(500).json({ success: false, message: "Server error" });
    }
  }
);

// LIST USERS
app.get("/glom/api/users/list", auth, async (req, res) => {
  try {
    const me = await User.findById(req.user.id).lean();
    if (!me)
      return res
        .status(404)
        .json({ success: false, message: "User not found" });

    let users;
    if (me.role === "MASTER") {
      users = await User.find({}).lean();
    } else if (me.role === "OWNER") {
      users = await User.find({
        $or: [{ parent: me.username }, { username: me.username }],
      }).lean();
    } else if (me.role === "SOURCE") {
      users = await User.find({
        $or: [{ parent: me.username }, { username: me.username }],
      }).lean();
    } else {
      users = [me];
    }

    res.json({ success: true, users });
  } catch (e) {
    console.error("USER LIST", e);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ======================= SIMPLE 2FA TOGGLE (PER-USER) =================
app.post("/glom/api/security/2fa/enable", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user)
      return res
        .status(404)
        .json({ success: false, message: "User not found" });

    if (user.twoFA?.enabled)
      return res.json({
        success: true,
        message: "2FA already enabled",
      });

    user.twoFA = {
      enabled: true,
      secret: randomKey(32),
    };
    await user.save();

    res.json({
      success: true,
      message: "2FA enabled",
      secret: user.twoFA.secret,
    });
  } catch (e) {
    console.error("2FA ENABLE", e);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/glom/api/security/2fa/disable", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user)
      return res
        .status(404)
        .json({ success: false, message: "User not found" });

    user.twoFA = { enabled: false, secret: "" };
    await user.save();

    res.json({ success: true, message: "2FA disabled" });
  } catch (e) {
    console.error("2FA DISABLE", e);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// DISCORD LINK PLACEHOLDER
app.post("/glom/api/security/discord/link", auth, async (req, res) => {
  try {
    const { discordId, discordName } = req.body;
    if (!discordId || !discordName)
      return res
        .status(400)
        .json({ success: false, message: "Missing discord data" });

    const user = await User.findById(req.user.id);
    if (!user)
      return res
        .status(404)
        .json({ success: false, message: "User not found" });

    user.discord = {
      linked: true,
      id: discordId,
      name: discordName,
    };
    await user.save();

    res.json({ success: true, message: "Discord linked" });
  } catch (e) {
    console.error("DISCORD LINK", e);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/glom/api/security/discord/unlink", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user)
      return res
        .status(404)
        .json({ success: false, message: "User not found" });

    user.discord = { linked: false, id: "", name: "" };
    await user.save();

    res.json({ success: true, message: "Discord unlinked" });
  } catch (e) {
    console.error("DISCORD UNLINK", e);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ======================= MASTER SECURITY CONTROL ======================
app.post(
  "/glom/api/master/disable-2fa",
  auth,
  allowRoles("MASTER"),
  async (req, res) => {
    try {
      const { username } = req.body;
      if (!username)
        return res
          .status(400)
          .json({ success: false, message: "Missing username" });

      const user = await User.findOne({ username });
      if (!user)
        return res
          .status(404)
          .json({ success: false, message: "User not found" });

      user.twoFA = { enabled: false, secret: "" };
      await user.save();

      res.json({
        success: true,
        message: "2FA disabled for user",
      });
    } catch (e) {
      console.error("MASTER DISABLE 2FA", e);
      res.status(500).json({ success: false, message: "Server error" });
    }
  }
);

app.post(
  "/glom/api/master/unlink-discord",
  auth,
  allowRoles("MASTER"),
  async (req, res) => {
    try {
      const { username } = req.body;
      if (!username)
        return res
          .status(400)
          .json({ success: false, message: "Missing username" });

      const user = await User.findOne({ username });
      if (!user)
        return res
          .status(404)
          .json({ success: false, message: "User not found" });

      user.discord = { linked: false, id: "", name: "" };
      await user.save();

      res.json({
        success: true,
        message: "Discord unlinked for user",
      });
    } catch (e) {
      console.error("MASTER UNLINK DISCORD", e);
      res.status(500).json({ success: false, message: "Server error" });
    }
  }
);

// ======================= HEALTH CHECK ==========================
app.get("/glom/api/ping", (req, res) => {
  res.json({
    success: true,
    message: "GLOM Authorization API is alive",
  });
});

// ======================= CATCH-ALL FOR FRONTEND ======================
// مهم: هذا لازم يكون بعد كل مسارات /glom/api عشان ما يكسرها
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "theme.html"));
});

// ======================= START SERVER ================================
app.listen(PORT, () => {
  console.log(`GLOM Authorization API running on port ${PORT}`);
});
