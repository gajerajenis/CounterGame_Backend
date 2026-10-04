require("dotenv").config();
const http = require("http");
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Server } = require("socket.io");

const { MONGO_URI, JWT_SECRET, CLIENT_URL = "*", PORT = 5000 } = process.env;

/* ---------- Models ---------- */
const User = mongoose.model(
  "User",
  new mongoose.Schema({
    firstName: { type: String, required: true, trim: true },
    lastName: { type: String, required: true, trim: true },
    mobile: { type: String, required: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
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

    if (await User.findOne({ email: email.toLowerCase().trim() }))
      return fail(res, 409, "EMAIL_EXISTS");

    const user = await User.create({
      firstName, lastName, mobile, email,
      password: await bcrypt.hash(password, 10),
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
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user || !(await bcrypt.compare(password, user.password)))
      return fail(res, 401, "BAD_CREDENTIALS");
    res.json({ token: signToken(user), user: pubUser(user) });
  } catch (e) {
    console.error(e);
    fail(res, 500, "SERVER");
  }
});

/* ---------- Auth middleware ---------- */
const auth = (req, res, next) => {
  try {
    const raw = (req.headers.authorization || "").replace("Bearer ", "");
    req.userId = jwt.verify(raw, JWT_SECRET).id;
    next();
  } catch {
    fail(res, 401, "UNAUTHORIZED");
  }
};

app.get("/api/users/search", auth, async (req, res) => {
  const q = String(req.query.q || "").trim();
  if (q.length < 2) return res.json({ users: [] });
  const rx = new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
  const users = await User.find({
    _id: { $ne: req.userId },
    $or: [{ firstName: rx }, { lastName: rx }, { email: rx }],
  }).limit(20);
  res.json({ users: users.map(pubUser) });
});

app.get("/api/messages/:otherId", auth, async (req, res) => {
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
});

app.get("/api/chats", auth, async (req, res) => {
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
      const msg = pubMsg(await Message.create({ from: socket.userId, to, text: body }));
      io.to(to).to(socket.userId).emit("message:new", msg); // dono ko
      cb?.({ ok: true });
    } catch (e) {
      console.error(e);
      cb?.({ ok: false });
    }
  });
});

mongoose
  .connect(MONGO_URI)
  .then(() => server.listen(PORT, () => console.log("Server on", PORT)))
  .catch((e) => console.error("Mongo error", e));