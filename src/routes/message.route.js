import express from "express";
import { handleMessage } from "../controllers/message.controller.js";
import { authMiddleware } from "../middleware/authMiddleware.js";

const router = express.Router();

router.post("/message", authMiddleware, handleMessage);

export default router;
