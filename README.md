# Volt Esports Backend

Production payment verification and notification gateway for Bluelock Esports / Volt Esports.

## Features
- Official Razorpay Order creation (`POST /api/payment/create-order`)
- Cryptographic HMAC-SHA256 signature verification & double validation (`POST /api/payment/verify`)
- Idempotent atomic wallet crediting via Supabase Service Role
- Razorpay webhook support (`POST /api/payment/webhook`)
- Health check monitoring (`GET /health`)
