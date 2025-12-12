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
const PORT = 3000;
const JWT_SECRET = process.env.JWT_SECRET || "GLOM_AUTH_SECRET_2025";
const GOFILE_TOKEN = process.env.GOFILE_TOKEN || "PASTE_GOFILE_API_TOKEN";
const MONGO_URI = process.env.MONGO_URI || "PASTE_MONGO_ATLAS_URI";

// ======================= EXPRESS INIT =====================
const app = express();
app.use(cors());
app.use(express.json());
app.use(useragent.express());

// Resolve __dirname (ESM)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ======================= DATABASE =========================
mongoose
  .connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("Mongo Connected ✔"))
  .catch((err) => console.log("DB ERROR ❌", err));

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
  owner: String, // created by (MASTER or OWNER username)
  loginMode: String, // USER_PASS | KEY | BOTH
  apiToken: String, // custom per product (for loader auth)
  allowedSources: [String], // usernames of SOURCE allowed to resell
  allowedPanels: [String], // usernames of PANEL allowed to use
  loaderLoginNote: String, // hint text ("Use KEY" / "Use USER+PASS")
});

// KEYS
const keySchema = new mongoose.Schema({
  productId: String,
  key: String,
  assignedUser: String, // PANEL username
  expires: Date,
});

// LOADER UPDATES
const updateSchema = new mongoose.Schema({
  productId: String,
  version: String,
  gofileContentId: String, // we store full gofile link or contentId
  note: String,
  uploadedBy: String,
  date: { type: Date, default: Date.now },
});

// SESSION LOG
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
  const exist = await User.findOne({ role: "MASTER" });
  if (!exist) {
    const hashed = await bcrypt.hash("JustSpecter0", 10);
    await User.create({
      username: "RAXX",
      password: hashed,
      role: "MASTER",
      parent: "SYSTEM",
    });
    console.log("MASTER AUTO CREATED ✔ Username: RAXX | Pass: JustSpecter0");
  }
}
autoCreateMaster();

// ======================= HELPERS ==========================
function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token)
    return res
      .status(401)
      .json({ success: false, message: "Unauthorized (no token)" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ success: false, message: "Invalid token" });
  }
}

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

async function trackSession(req, userId, username) {
  const ip =
    req.headers["x-forwarded-for"] ||
    req.socket.remoteAddress ||
    "UnknownIP";

  const geo = geoip.lookup(ip) || {};

  await Session.create({
    userId,
    username,
    ip,
    device: req.useragent.platform,
    os: req.useragent.os,
    browser: req.useragent.browser,
    country: geo.country || "N/A",
    city: geo.city || "N/A",
  });
}

function randomKey(len = 32) {
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let r = "";
  for (let i = 0; i < len; i++) {
    r += chars[Math.floor(Math.random() * chars.length)];
  }
  return r;
}

// ======================= PANEL UI ROUTES =============================
// كل الواجهة في theme.html
function serveTheme(req, res) {
  res.sendFile(path.join(__dirname, "theme.html"));
}

app.get("/", serveTheme);
app.get("/auth", serveTheme);
app.get("/auth/login", serveTheme);
app.get("/auth/*", serveTheme);

// ======================= AUTH ROUTES =================================

// LOGIN
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

    const token = jwt.sign(
      {
        id: user._id.toString(),
        username: user.username,
        role: user.role,
      },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

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

// CURRENT USER
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
    console.error("AUTH ME ERROR", e);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ======================= PRODUCT ROUTES ===============================

// CREATE PRODUCT (MASTER + OWNER)
// loginMode: "USER_PASS" | "KEY" | "BOTH"
// apiToken optional → auto generate
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
        return res
          .status(400)
          .json({ success: false, message: "API token already used" });

      const doc = await Product.create({
        name,
        owner: req.user.username, // owner = من صنع المنتج
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

// LIST PRODUCTS (role aware)
// MASTER + OWNER : كل المنتجات
// SOURCE : المنتجات المسموح له بها
// PANEL : المنتجات المرتبطة بالبنل
app.get("/glom/api/products/list", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).lean();
    if (!user)
      return res
        .status(404)
        .json({ success: false, message: "User not found" });

    let products = [];

    if (user.role === "MASTER" || user.role === "OWNER") {
      products = await Product.find({}).lean();
    } else if (user.role === "SOURCE") {
      products = await Product.find({ allowedSources: user.username }).lean();
    } else if (user.role === "PANEL") {
      products = await Product.find({ allowedPanels: user.username }).lean();
    } else {
      return res
        .status(403)
        .json({ success: false, message: "Role not supported" });
    }

    // إخفاء API عن SOURCE و PANEL
    if (user.role !== "MASTER" && user.role !== "OWNER") {
      products = products.map((p) => {
        const { apiToken, ...rest } = p;
        return rest;
      });
    }

    // إضافة رابط API (MASTER + OWNER فقط)
    if (user.role === "MASTER" || user.role === "OWNER") {
      const baseUrl =
        process.env.PUBLIC_BASE_URL || "https://my-src-a5iw.onrender.com";
      products = products.map((p) => ({
        ...p,
        apiLink: `${baseUrl}/glom/api/loader/check?apiToken=${encodeURIComponent(
          p.apiToken
        )}`,
      }));
    }

    res.json({ success: true, products });
  } catch (e) {
    console.error("PRODUCT LIST", e);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// UPDATE PRODUCT (MASTER + OWNER) — نفس الصلاحيات على كل المنتجات
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
          return res
            .status(400)
            .json({ success: false, message: "API token already used" });
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

      await Product.deleteOne({ _id: productId });
      await Key.deleteMany({ productId });
      await Update.deleteMany({ productId });

      res.json({
        success: true,
        message: "Product & related keys/updates deleted",
      });
    } catch (e) {
      console.error("PRODUCT DELETE", e);
      res.status(500).json({ success: false, message: "Server error" });
    }
  }
);

// ASSIGN PRODUCT TO SOURCE (MASTER + OWNER)
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

      const srcUser = await User.findOne({
        username: sourceUsername,
        role: "SOURCE",
      });
      if (!srcUser)
        return res
          .status(404)
          .json({ success: false, message: "Source not found" });

      if (!prod.allowedSources.includes(sourceUsername)) {
        prod.allowedSources.push(sourceUsername);
        await prod.save();
      }

      res.json({ success: true, product: prod });
    } catch (e) {
      console.error("ASSIGN SOURCE", e);
      res.status(500).json({ success: false, message: "Server error" });
    }
  }
);

// ASSIGN PRODUCT TO PANEL (MASTER + OWNER + SOURCE)
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

      // SOURCE لازم يكون عنده صلاحية على المنتج
      if (
        req.user.role === "SOURCE" &&
        !prod.allowedSources.includes(req.user.username)
      ) {
        return res
          .status(403)
          .json({ success: false, message: "You don't have this product" });
      }

      const pnl = await User.findOne({
        username: panelUsername,
        role: "PANEL",
      });
      if (!pnl)
        return res
          .status(404)
          .json({ success: false, message: "Panel not found" });

      if (!prod.allowedPanels.includes(panelUsername)) {
        prod.allowedPanels.push(panelUsername);
        await prod.save();
      }

      res.json({ success: true, product: prod });
    } catch (e) {
      console.error("ASSIGN PANEL", e);
      res.status(500).json({ success: false, message: "Server error" });
    }
  }
);

// ======================= KEYS ========================================

// CREATE KEYS (MASTER + OWNER + SOURCE)
// body: { productId, panelUsername, days, count }
app.post(
  "/glom/api/keys/create",
  auth,
  allowRoles("MASTER", "OWNER", "SOURCE"),
  async (req, res) => {
    try {
      const { productId, panelUsername, days, count } = req.body;
      if (!productId || !panelUsername)
        return res
          .status(400)
          .json({ success: false, message: "Missing fields" });

      const prod = await Product.findById(productId);
      if (!prod)
        return res
          .status(404)
          .json({ success: false, message: "Product not found" });

      // SOURCE لازم يكون عنده المنتج
      if (
        req.user.role === "SOURCE" &&
        !prod.allowedSources.includes(req.user.username)
      ) {
        return res
          .status(403)
          .json({ success: false, message: "You don't have this product" });
      }

      if (!prod.allowedPanels.includes(panelUsername)) {
        return res.status(403).json({
          success: false,
          message: "Panel not assigned for this product",
        });
      }

      const pnl = await User.findOne({
        username: panelUsername,
        role: "PANEL",
      });
      if (!pnl)
        return res
          .status(404)
          .json({ success: false, message: "Panel user not found" });

      const total = Number(count) > 0 ? Number(count) : 1;
      const created = [];

      for (let i = 0; i < total; i++) {
        const keyValue = randomKey(40);

        let expires = null;
        if (days && Number(days) > 0) {
          expires = new Date(Date.now() + Number(days) * 86400000);
        }

        const doc = await Key.create({
          productId,
          key: keyValue,
          assignedUser: panelUsername,
          expires,
        });

        created.push({
          id: doc._id,
          key: keyValue,
          expires,
        });
      }

      res.json({
        success: true,
        count: created.length,
        keys: created,
      });
    } catch (e) {
      console.error("KEY CREATE", e);
      res.status(500).json({ success: false, message: "Server error" });
    }
  }
);

// LIST KEYS (role aware)
app.get("/glom/api/keys/list", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).lean();
    if (!user)
      return res
        .status(404)
        .json({ success: false, message: "User not found" });

    let keys = [];

    if (user.role === "MASTER" || user.role === "OWNER") {
      keys = await Key.find({}).lean();
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
    const license = await Key.findOne({
      productId: prod._id.toString(),
      key,
    });
    if (!license)
      return res.json({
        success: false,
        status: "no_key",
        message: "Key not found",
      });

    if (license.expires && license.expires < now)
      return res.json({
        success: false,
        status: "expired",
        message: "Key expired",
      });

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

// PUSH UPDATE (MASTER + OWNER)
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

// ======================= USERS / RESELLERS ============================

// CREATE USER (RESELLER)
// MASTER: create OWNER / SOURCE / PANEL
// OWNER : create SOURCE / PANEL (NOT OWNER)
// SOURCE: create PANEL only
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

      // OWNER cannot create OWNER
      if (req.user.role === "OWNER" && role === "OWNER") {
        return res.status(403).json({
          success: false,
          message: "OWNER cannot create another OWNER",
        });
      }

      // SOURCE can only create PANEL
      if (req.user.role === "SOURCE" && role !== "PANEL") {
        return res.status(403).json({
          success: false,
          message: "SOURCE can only create PANEL",
        });
      }

      const exists = await User.findOne({ username });
      if (exists)
        return res
          .status(400)
          .json({ success: false, message: "Username already used" });

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

// LIST USERS (tree)
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
      users = [me]; // PANEL يشوف نفسه فقط
    }

    res.json({ success: true, users });
  } catch (e) {
    console.error("USER LIST", e);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ======================= SIMPLE SECURITY (2FA + DISCORD) =============

// Enable 2FA (self)
app.post("/glom/api/security/2fa/enable", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user)
      return res
        .status(404)
        .json({ success: false, message: "User not found" });

    if (user.twoFA?.enabled)
      return res.json({ success: true, message: "2FA already enabled" });

    user.twoFA = { enabled: true, secret: randomKey(32) };
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

// Disable 2FA (self)
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

// Link Discord (placeholder)
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

    user.discord = { linked: true, id: discordId, name: discordName };
    await user.save();

    res.json({ success: true, message: "Discord linked" });
  } catch (e) {
    console.error("DISCORD LINK", e);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Unlink Discord (self)
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

// MASTER: force disable 2FA for any user
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

      res.json({ success: true, message: "2FA disabled for user" });
    } catch (e) {
      console.error("MASTER DISABLE 2FA", e);
      res.status(500).json({ success: false, message: "Server error" });
    }
  }
);

// MASTER: force unlink Discord
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

      res.json({ success: true, message: "Discord unlinked for user" });
    } catch (e) {
      console.error("MASTER UNLINK DISCORD", e);
      res.status(500).json({ success: false, message: "Server error" });
    }
  }
);

// ======================= HEALTH CHECK =====================
app.get("/glom/api/ping", (req, res) => {
  res.json({ success: true, message: "GLOM Authorization API is alive" });
});

// ======================= START SERVER =====================
app.listen(PORT, () => {
  console.log(`GLOM Authorization API running on port ${PORT}`);
});
