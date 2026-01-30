import express from "express";
import dotenv from "dotenv";
import messageRoutes from "./routes/message.route.js";

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

app.use(express.json());
app.use("/api/v1", messageRoutes);

app.listen(port, () => {
  console.log(`Minimal classifier listening on port ${port}`);
});
