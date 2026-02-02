export function authMiddleware(req, res, next) {
  const apiKey = process.env.API_KEY;

  if (!apiKey) {
    console.error("[Auth] API key not configured");
    return res
      .status(400)
      .json({
        status: "failed",
        reply: "",
        message: "API key not configured",
      });
  }

  if (req.header("x-api-key") !== apiKey) {
    console.error("[Auth] Unauthorized", {
      provided: req.header("x-api-key"),
      expected: apiKey,
    });
    return res.status(400).json({
      status: "failed",
      reply: "",
      message: "Unauthorized",
    });
  }

  return next();
}
