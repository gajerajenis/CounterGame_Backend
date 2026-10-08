require("dotenv").config({ path: require("path").join(__dirname, "../.env") });
const http = require("http");
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Server } = require("socket.io");

const {
  MONGO_URI,
  JWT_SECRET,
  ADMIN_EMAIL = "",
  ADMIN_PASSWORD = "",
  CLIENT_URL = "*",
  PORT = 5000,
} = process.env;

const adminEmail = ADMIN_EMAIL.toLowerCase().trim();

/* ---------- Models ---------- */
const User = mongoose.model(
  "User",
  new mongoose.Schema({
    firstName: { type: String, required: true, trim: true },
    lastName: { type: String, required: true, trim: true },
    mobile: { type: String, required: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    role: { type: String, enum: ["user", "admin"], default: "user" },
    chatEnabled: { type: Boolean, default: false },
  })
);

const Message = mongoose.model(
  "Message",
  new mongoose.Schema(
    {
      from: { type: mongoose.Schema.Types.ObjectId, ref: "User", index: true },
      to: { type: mongoose.Schema.Types.ObjectId, ref: "User", index: true },
      text: { type: String, required: true, maxlength: 1000 },
    },
    { timestamps: { createdAt: true, updatedAt: false } }
  )
);

/* ---------- Helpers ---------- */
const pubUser = (u) => ({
  id: String(u._id),
  firstName: u.firstName,
  lastName: u.lastName,
  mobile: u.mobile,
  email: u.email,
  role: u.role,
  chatEnabled: u.role === "admin" ? true : !!u.chatEnabled,
});

const pubMsg = (m) => ({
  _id: String(m._id),
  from: String(m.from),
  to: String(m.to),
  text: m.text,
  createdAt: m.createdAt,
});

const signToken = (u) => jwt.sign({ id: String(u._id) }, JWT_SECRET, { expiresIn: "30d" });
const fail = (res, status, code) => res.status(status).json({ code });
const canChatUser = (u) => !!u && (u.role === "admin" || !!u.chatEnabled);

/* ---------- Admin seed (fix admin: email + password .env se) ---------- */
const seedAdmin = async () => {
  if (!adminEmail || !ADMIN_PASSWORD) {
    console.warn("ADMIN_EMAIL / ADMIN_PASSWORD .env me nahi hai, admin nahi banega");
    return;
  }
  const hash = await bcrypt.hash(ADMIN_PASSWORD, 10);

  // admin banao ya update karo (password hamesha .env se sync)
  await User.updateOne(
    { email: adminEmail },
    {
      $set: { password: hash, role: "admin", chatEnabled: true },
      $setOnInsert: { firstName: "Admin", lastName: "Math Rush", mobile: "0000000000" },
    },
    { upsert: true }
  );

  // sirf ek hi admin rahe
  await User.updateMany({ email: { $ne: adminEmail }, role: "admin" }, { role: "user" });
  console.log("Admin ready:", adminEmail);
};

/* ---------- Express ---------- */
const app = express();
app.use(cors({ origin: CLIENT_URL === "*" ? true : CLIENT_URL.split(",") }));
app.use(express.json());

app.get("/health", (_, res) => res.json({ ok: true }));

app.post("/api/auth/signup", async (req, res) => {
  try {
    const { firstName, lastName, mobile, email, password } = req.body || {};
    if (![firstName, lastName, mobile, email, password].every((v) => v && String(v).trim()))
      return fail(res, 400, "FIELDS_REQUIRED");
    if (!/^\S+@\S+\.\S+$/.test(email)) return fail(res, 400, "INVALID_EMAIL");
    if (!/^\d{10}$/.test(mobile)) return fail(res, 400, "INVALID_MOBILE");
    if (String(password).length < 6) return fail(res, 400, "WEAK_PASSWORD");

    const mail = email.toLowerCase().trim();

    // admin email se koi signup nahi kar sakta
    if (mail === adminEmail) return fail(res, 409, "EMAIL_EXISTS");
    if (await User.findOne({ email: mail })) return fail(res, 409, "EMAIL_EXISTS");

    const user = await User.create({
      firstName,
      lastName,
      mobile,
      email: mail,
      password: await bcrypt.hash(password, 10),
      role: "user",
      chatEnabled: false,
    });
    res.json({ token: signToken(user), user: pubUser(user) });
  } catch (e) {
    console.error(e);
    fail(res, 500, "SERVER");
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return fail(res, 400, "FIELDS_REQUIRED");
    const user = await User.findOne({ email: String(email).toLowerCase().trim() });
    if (!user || !(await bcrypt.compare(password, user.password)))
      return fail(res, 401, "BAD_CREDENTIALS");
    res.json({ token: signToken(user), user: pubUser(user) });
  } catch (e) {
    console.error(e);
    fail(res, 500, "SERVER");
  }
});

/* ---------- Auth middleware ---------- */
const auth = async (req, res, next) => {
  try {
    const raw = (req.headers.authorization || "").replace("Bearer ", "");
    const { id } = jwt.verify(raw, JWT_SECRET);
    const user = await User.findById(id);
    if (!user) return fail(res, 401, "UNAUTHORIZED");
    req.userId = String(user._id);
    req.user = user;
    next();
  } catch {
    fail(res, 401, "UNAUTHORIZED");
  }
};

const chatOnly = (req, res, next) =>
  canChatUser(req.user) ? next() : fail(res, 403, "NO_CHAT_ACCESS");

const adminOnly = (req, res, next) =>
  req.user.role === "admin" ? next() : fail(res, 403, "FORBIDDEN");

// app khulte hi session + permission refresh
app.get("/api/auth/me", auth, (req, res) => res.json({ user: pubUser(req.user) }));

/* ---------- Admin routes ---------- */
app.get("/api/admin/users", auth, adminOnly, async (req, res) => {
  try {
    const users = await User.find({ _id: { $ne: req.userId } }).sort({ _id: -1 });
    res.json({ users: users.map(pubUser) });
  } catch (e) {
    console.error(e);
    fail(res, 500, "SERVER");
  }
});

app.patch("/api/admin/users/:id", auth, adminOnly, async (req, res) => {
  try {
    const { id } = req.params;
    const { chatEnabled } = req.body || {};
    if (!mongoose.isValidObjectId(id) || typeof chatEnabled !== "boolean")
      return fail(res, 400, "SERVER");

    const u = await User.findOneAndUpdate(
      { _id: id, role: { $ne: "admin" } },
      { chatEnabled },
      { new: true }
    );
    if (!u) return fail(res, 404, "SERVER");

    io.to(id).emit("user:updated", pubUser(u)); // user ko live pata chale
    res.json({ user: pubUser(u) });
  } catch (e) {
    console.error(e);
    fail(res, 500, "SERVER");
  }
});

/* ---------- Chat routes (sirf permission wale) ---------- */
app.get("/api/users/search", auth, chatOnly, async (req, res) => {
  try {
    const q = String(req.query.q || "").trim();
    if (q.length < 2) return res.json({ users: [] });
    const rx = new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
    const users = await User.find({
      _id: { $ne: req.userId },
      $and: [
        { $or: [{ chatEnabled: true }, { role: "admin" }] }, // sirf chat-allowed log dikhenge
        { $or: [{ firstName: rx }, { lastName: rx }, { email: rx }] },
      ],
    }).limit(20);
    res.json({ users: users.map(pubUser) });
  } catch (e) {
    console.error(e);
    fail(res, 500, "SERVER");
  }
});

app.get("/api/messages/:otherId", auth, chatOnly, async (req, res) => {
  try {
    const { otherId } = req.params;
    if (!mongoose.isValidObjectId(otherId)) return fail(res, 400, "SERVER");
    const messages = await Message.find({
      $or: [
        { from: req.userId, to: otherId },
        { from: otherId, to: req.userId },
      ],
    })
      .sort({ createdAt: 1 })
      .limit(500);
    res.json({ messages: messages.map(pubMsg) });
  } catch (e) {
    console.error(e);
    fail(res, 500, "SERVER");
  }
});

app.get("/api/chats", auth, chatOnly, async (req, res) => {
  try {
    const msgs = await Message.find({ $or: [{ from: req.userId }, { to: req.userId }] })
      .sort({ createdAt: -1 })
      .limit(1000);
    const lastByUser = new Map();
    for (const m of msgs) {
      const other = String(m.from) === req.userId ? String(m.to) : String(m.from);
      if (!lastByUser.has(other)) lastByUser.set(other, m);
    }
    const users = await User.find({ _id: { $in: [...lastByUser.keys()] } });
    const chats = users
      .map((u) => {
        const m = lastByUser.get(String(u._id));
        return {
          user: pubUser(u),
          last: { from: String(m.from), text: m.text, createdAt: m.createdAt },
        };
      })
      .sort((a, b) => new Date(b.last.createdAt) - new Date(a.last.createdAt));
    res.json({ chats });
  } catch (e) {
    console.error(e);
    fail(res, 500, "SERVER");
  }
});

/* ---------- Socket.io ---------- */
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: CLIENT_URL === "*" ? true : CLIENT_URL.split(",") },
});

io.use((socket, next) => {
  try {
    socket.userId = jwt.verify(socket.handshake.auth?.token, JWT_SECRET).id;
    next();
  } catch {
    next(new Error("AUTH"));
  }
});

io.on("connection", (socket) => {
  socket.join(socket.userId); // har user ka apna room

  socket.on("message:send", async ({ to, text } = {}, cb) => {
    try {
      const body = String(text || "").trim().slice(0, 1000);
      if (!body || !mongoose.isValidObjectId(to)) return cb?.({ ok: false });

      const [me, other] = await Promise.all([
        User.findById(socket.userId).select("role chatEnabled"),
        User.findById(to).select("role chatEnabled"),
      ]);
      if (!canChatUser(me) || !canChatUser(other))
        return cb?.({ ok: false, code: "NO_CHAT_ACCESS" });

      const msg = pubMsg(await Message.create({ from: socket.userId, to, text: body }));
      io.to(to).to(socket.userId).emit("message:new", msg); // dono ko
      cb?.({ ok: true });
    } catch (e) {
      console.error(e);
      cb?.({ ok: false });
    }
  });
});

/* ---------- Start ---------- */
mongoose
  .connect(MONGO_URI)
  .then(async () => {
    await seedAdmin();
    server.listen(PORT, () => console.log("Server on", PORT));
  })
  .catch((e) => console.error("Mongo error", e));