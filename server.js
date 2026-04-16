import express from "express";
import cors from "cors";
import "dotenv/config";
import Razorpay from "razorpay";
import crypto from "crypto";

const app = express();

// 1. Updated CORS to handle standard React/Vite ports
app.use(
  cors({
    origin: ["http://localhost:3000", "http://localhost:5173"],
  }),
);
app.use(express.json());

const razorpayInstance = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// Create Order Endpoint
app.post("/create-order", async (req, res) => {
  try {
    const { amount, currency = "INR" } = req.body;

    if (!amount) {
      return res
        .status(400)
        .json({ success: false, error: "Amount is required" });
    }

    const options = {
      amount: Math.round(amount * 100), // Ensure it's an integer (paise)
      currency,
      receipt: `rcpt_${Date.now()}`,
    };

    const order = await razorpayInstance.orders.create(options);

    // MATCH THIS WITH FRONTEND: sending 'id' instead of 'orderId'
    res.status(200).json({
      id: order.id,
      amount: order.amount,
      currency: order.currency,
    });
  } catch (error) {
    console.error("Order Creation Error:", error);
    res.status(500).json({ error: "Failed to create order" });
  }
});

// Verify Payment Endpoint
app.post("/verify-payment", (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } =
      req.body;

    // Validation: Ensure all pieces are present
    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      return res
        .status(400)
        .json({ success: false, error: "Missing payment details" });
    }

    const sign = razorpay_order_id + "|" + razorpay_payment_id;

    const expectedSignature = crypto
      .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
      .update(sign.toString())
      .digest("hex");

    if (expectedSignature === razorpay_signature) {
      // Payment is authentic
      res.status(200).json({
        success: true,
        message: "Payment verified successfully",
        razorpay_payment_id, // Returning only what you requested
      });
    } else {
      res
        .status(400)
        .json({
          success: false,
          error: "Invalid signature (Payment tampered)",
        });
    }
  } catch (error) {
    console.error("Verification Error:", error);
    res.status(500).json({ success: false, error: "Internal Server Error" });
  }
});

const PORT = process.env.PORT || 8000; // Using 8000 as per your frontend fetch
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
