import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB conectado"))
  .catch(err => console.error(err));

const KeySchema = new mongoose.Schema({
  key: String,
  active: Boolean,
  hwid: String
});

const Key = mongoose.model("Key", KeySchema);

app.post("/validate", async (req, res) => {
  const { key, hwid } = req.body;

  const data = await Key.findOne({ key });
  if (!data) return res.status(401).json({ ok: false });

  if (data.active && data.hwid !== hwid) {
    return res.status(403).json({ ok: false });
  }

  if (!data.active) {
    data.active = true;
    data.hwid = hwid;
    await data.save();
  }

  res.json({ ok: true });
});

app.get("/", (_, res) => {
  res.send("API Online");
});

app.listen(process.env.PORT || 3000, () => {
  console.log("API rodando");
});
