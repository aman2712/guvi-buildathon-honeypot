import express from "express";
import dotenv from "dotenv";
import messageRoutes from "./routes/message.route.js";

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

app.use("/api/v1", messageRoutes);

app.get("/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

app.listen(port, () => {
  console.log(`Minimal classifier listening on port ${port}`);
});


app.use((err, req, res, next) => {
  console.error("[Express] Unhandled middleware error", err);
  if (err.type === "entity.parse.failed") {
    return res.status(400).json({
      status: "failed",
      reply: "",
      message: "Invalid JSON body",
    });
  }
  res.status(400).json({
    status: "failed",
    reply: "",
    message: "Request failed",
  });
});
