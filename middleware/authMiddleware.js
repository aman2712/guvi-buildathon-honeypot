export function authMiddleware(req, res, next) {
  const apiKey = process.env.API_KEY;

  if (!apiKey) {
    return res
      .status(500)
      .json({ status: "error", message: "API key not configured" });
  }

  if (req.header("x-api-key") !== apiKey) {
    return res.status(401).json({ status: "error", message: "Unauthorized" });
  }

  return next();
}
