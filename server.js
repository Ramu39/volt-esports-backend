import express from 'express';
import cors from 'cors';
import crypto from 'crypto';
import Razorpay from 'razorpay';
import bcrypt from 'bcryptjs';
import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';

dotenv.config();

const PORT = process.env.PORT || 10000;
const RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID || '';
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET || '';
const CASHFREE_APP_ID = process.env.CASHFREE_APP_ID || '';
const CASHFREE_SECRET_KEY = process.env.CASHFREE_SECRET_KEY || '';
const CASHFREE_ENV = process.env.CASHFREE_ENV || 'sandbox';
const CASHFREE_BASE_URL = CASHFREE_ENV === 'production'
  ? 'https://api.cashfree.com/pg'
  : 'https://sandbox.cashfree.com/pg';
const CASHFREE_API_VERSION = '2023-08-01';

const SUPABASE_URL = process.env.SUPABASE_URL || 'https://dkcljpfwvlvdcwyivhyf.supabase.co';
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

const razorpay = new Razorpay({
  key_id: RAZORPAY_KEY_ID,
  key_secret: RAZORPAY_KEY_SECRET,
});

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: {
    persistSession: false,
    autoRefreshToken: false,
  }
});

const app = express();

app.use(cors());
app.use(express.json());

// Health Check
app.get('/', (req, res) => {
  res.json({
    status: 'ok',
    service: 'volt-esports-backend',
    version: '1.1.0',
    timestamp: new Date().toISOString(),
    cashfreeConfigured: !!(CASHFREE_APP_ID && CASHFREE_SECRET_KEY),
    razorpayConfigured: !!(RAZORPAY_KEY_ID && RAZORPAY_KEY_SECRET),
    supabaseConfigured: !!(SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY)
  });
});

app.get('/health', (req, res) => {
  res.status(200).send('OK');
});

/**
 * AUTHENTICATION: REGISTER
 * POST /api/auth/register
 * Request Body: { username, fullName, phone, email, password, ffIgn }
 */
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, fullName, phone, email, password, ffIgn } = req.body;

    if (!username || !fullName || !phone || !email || !password) {
      return res.status(400).json({ success: false, message: 'All fields are required.' });
    }

    if (password.length < 6) {
      return res.status(400).json({ success: false, message: 'Password must be at least 6 characters.' });
    }

    const cleanUsername = username.trim();
    const cleanEmail = email.trim().toLowerCase();

    // Check duplicate
    const { data: existing, error: checkErr } = await supabase
      .from('profiles')
      .select('id, username, email')
      .or(`username.ilike.${cleanUsername},email.ilike.${cleanEmail}`)
      .maybeSingle();

    if (existing) {
      if (existing.username.toLowerCase() === cleanUsername.toLowerCase()) {
        return res.status(400).json({ success: false, message: 'Username is already taken.' });
      }
      return res.status(400).json({ success: false, message: 'Email is already registered.' });
    }

    // Hash password with bcrypt (10 rounds)
    const passwordHash = await bcrypt.hash(password, 10);

    // Insert into profiles
    const { data: newProfile, error: pErr } = await supabase
      .from('profiles')
      .insert([{
        username: cleanUsername,
        full_name: fullName.trim(),
        phone: phone.trim(),
        email: cleanEmail,
        password_hash: passwordHash,
        free_fire_ign: ffIgn ? ffIgn.trim() : '',
        free_fire_uid: '',
        is_admin: false,
        is_banned: false,
        created_at: new Date().toISOString()
      }])
      .select()
      .single();

    if (pErr) {
      console.error('[Auth] Register profile insert error:', pErr);
      return res.status(500).json({ success: false, message: pErr.message || 'Registration failed' });
    }

    // Create 0-coin wallet
    try {
      await supabase
        .from('wallets')
        .insert([{
          user_id: newProfile.id,
          balance: 0,
          winning_balance: 0,
          updated_at: new Date().toISOString()
        }]);
    } catch (wEx) {
      console.warn('[Auth] Wallet creation warning:', wEx.message);
    }

    console.log(`[Auth] User registered with bcrypt: ${newProfile.username} (${newProfile.id})`);

    return res.status(201).json({
      success: true,
      message: 'Account created successfully!',
      user: {
        id: newProfile.id,
        username: newProfile.username,
        name: newProfile.full_name,
        phone: newProfile.phone,
        email: newProfile.email,
        ffIgn: newProfile.free_fire_ign,
        walletBalance: 0,
        winningBalance: 0,
        isAdmin: false
      }
    });
  } catch (err) {
    console.error('[Auth] Register exception:', err);
    return res.status(500).json({ success: false, message: err.message || 'Server error during registration' });
  }
});

/**
 * AUTHENTICATION: LOGIN
 * POST /api/auth/login
 * Request Body: { identifier, password }
 */
app.post('/api/auth/login', async (req, res) => {
  try {
    const { identifier, password } = req.body;

    if (!identifier || !password) {
      return res.status(400).json({ success: false, message: 'Username/Email and Password are required.' });
    }

    const cleanId = identifier.trim().toLowerCase();

    // Query user
    const { data: user, error: uErr } = await supabase
      .from('profiles')
      .select('*')
      .or(`username.ilike.${cleanId},email.ilike.${cleanId}`)
      .maybeSingle();

    if (uErr) {
      console.error('[Auth] Login query error:', uErr);
      return res.status(500).json({ success: false, message: 'Database error during login' });
    }

    if (!user) {
      return res.status(404).json({ success: false, message: 'Account not found. Please Sign Up.' });
    }

    if (user.is_banned) {
      return res.status(403).json({
        success: false,
        message: `Account is banned: ${user.ban_reason || 'Violation of rules'}`
      });
    }

    // Verify password (bcrypt or seamless upgrade from legacy plaintext)
    let isValidPassword = false;
    let needsUpgrade = false;

    if (user.password_hash) {
      if (
        user.password_hash.startsWith('$2a$') ||
        user.password_hash.startsWith('$2b$') ||
        user.password_hash.startsWith('$2y$')
      ) {
        isValidPassword = await bcrypt.compare(password, user.password_hash);
      } else if (user.password_hash === password) {
        isValidPassword = true;
        needsUpgrade = true;
      }
    }

    if (!isValidPassword) {
      return res.status(401).json({ success: false, message: 'Incorrect password.' });
    }

    // Seamless migration: upgrade legacy plaintext password to bcrypt hash
    if (needsUpgrade) {
      console.log(`[Auth] Upgrading legacy password to bcrypt for user: ${user.username}`);
      const upgradedHash = await bcrypt.hash(password, 10);
      await supabase
        .from('profiles')
        .update({ password_hash: upgradedHash })
        .eq('id', user.id);
    }

    // Fetch wallet
    const { data: wallet } = await supabase
      .from('wallets')
      .select('balance, winning_balance')
      .eq('user_id', user.id)
      .maybeSingle();

    return res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        name: user.full_name || '',
        phone: user.phone || '',
        email: user.email || '',
        ffIgn: user.free_fire_ign || '',
        walletBalance: Number(wallet?.balance || 0),
        winningBalance: Number(wallet?.winning_balance || 0),
        isAdmin: !!user.is_admin
      }
    });
  } catch (err) {
    console.error('[Auth] Login exception:', err);
    return res.status(500).json({ success: false, message: err.message || 'Server error during login' });
  }
});

/**
 * ==============================================================================
 * CASHFREE PAYMENT GATEWAY ENDPOINTS
 * ==============================================================================
 */

/**
 * 1. CASHFREE: CREATE ORDER
 * POST /api/cashfree/create-order
 * Request Body: { userId, amount, email, phone, name }
 */
app.post('/api/cashfree/create-order', async (req, res) => {
  try {
    const { userId, amount, email, phone, name } = req.body;

    if (!userId) {
      return res.status(400).json({ success: false, message: 'User ID is required' });
    }

    const numAmount = Number(amount);
    if (isNaN(numAmount) || numAmount < 10) {
      return res.status(400).json({ success: false, message: 'Minimum deposit amount is 10 Coins' });
    }

    const cleanUserId = String(userId).replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 30);
    const orderId = `cf_${cleanUserId.slice(0, 8)}_${Date.now()}`;
    const cleanPhone = (phone && String(phone).replace(/[^0-9]/g, '').length >= 10) 
      ? String(phone).replace(/[^0-9]/g, '').slice(-10) 
      : '9999999999';
    const cleanEmail = email && email.includes('@') ? email.trim() : 'gamer@bluelock.esports';
    const cleanName = name && name.trim() ? name.trim() : 'Player';

    const orderPayload = {
      order_id: orderId,
      order_amount: numAmount,
      order_currency: 'INR',
      customer_details: {
        customer_id: cleanUserId,
        customer_phone: cleanPhone,
        customer_name: cleanName,
        customer_email: cleanEmail
      },
      order_meta: {
        notify_url: 'https://volt-esports-backend.onrender.com/api/cashfree/webhook'
      },
      order_note: `Deposit ${numAmount} Coins`
    };

    console.log(`[Cashfree] Creating order: ${orderId}, amount: ₹${numAmount} for user: ${userId}`);

    const cfRes = await fetch(`${CASHFREE_BASE_URL}/orders`, {
      method: 'POST',
      headers: {
        'x-client-id': CASHFREE_APP_ID,
        'x-client-secret': CASHFREE_SECRET_KEY,
        'x-api-version': CASHFREE_API_VERSION,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(orderPayload)
    });

    const cfData = await cfRes.json();

    if (!cfRes.ok || !cfData.payment_session_id) {
      console.error('[Cashfree] Order creation failed:', cfRes.status, cfData);
      return res.status(cfRes.status >= 400 && cfRes.status < 500 ? cfRes.status : 500).json({
        success: false,
        message: cfData.message || 'Failed to create Cashfree order'
      });
    }

    console.log(`[Cashfree] Order created successfully: ${cfData.order_id}, session: ${cfData.payment_session_id.slice(0, 15)}...`);

    return res.json({
      success: true,
      orderId: cfData.order_id,
      paymentSessionId: cfData.payment_session_id,
      amount: cfData.order_amount,
      currency: cfData.order_currency,
      environment: CASHFREE_ENV,
      appId: CASHFREE_APP_ID
    });
  } catch (error) {
    console.error('[Cashfree] create-order exception:', error);
    return res.status(500).json({
      success: false,
      message: error.message || 'Server error creating Cashfree order'
    });
  }
});

/**
 * 2. CASHFREE: VERIFY PAYMENT & ATOMIC WALLET CREDIT
 * POST /api/cashfree/verify
 * Request Body: { orderId, userId }
 */
app.post('/api/cashfree/verify', async (req, res) => {
  try {
    const { orderId, userId } = req.body;

    if (!orderId || !userId) {
      return res.status(400).json({
        success: false,
        message: 'Missing required parameters: orderId and userId'
      });
    }

    console.log(`[Cashfree] Verifying order: ${orderId} for user: ${userId}`);

    // 1. Fetch order details directly from Cashfree PG API
    const orderRes = await fetch(`${CASHFREE_BASE_URL}/orders/${orderId}`, {
      headers: {
        'x-client-id': CASHFREE_APP_ID,
        'x-client-secret': CASHFREE_SECRET_KEY,
        'x-api-version': CASHFREE_API_VERSION
      }
    });

    if (!orderRes.ok) {
      const errText = await orderRes.text();
      console.error(`[Cashfree] Failed to fetch order ${orderId}:`, orderRes.status, errText);
      return res.status(orderRes.status).json({
        success: false,
        message: 'Could not fetch order status from Cashfree.'
      });
    }

    const orderData = await orderRes.json();
    console.log(`[Cashfree] Order ${orderId} status: ${orderData.order_status}, amount: ${orderData.order_amount}`);

    const isPaid = orderData.order_status === 'PAID';
    if (!isPaid) {
      return res.status(400).json({
        success: false,
        orderStatus: orderData.order_status,
        message: `Payment not completed. Current status: ${orderData.order_status}`
      });
    }

    const numAmount = Number(orderData.order_amount);

    // 2. Fetch payments to get cf_payment_id if available
    let paymentId = orderId;
    try {
      const payRes = await fetch(`${CASHFREE_BASE_URL}/orders/${orderId}/payments`, {
        headers: {
          'x-client-id': CASHFREE_APP_ID,
          'x-client-secret': CASHFREE_SECRET_KEY,
          'x-api-version': CASHFREE_API_VERSION
        }
      });
      if (payRes.ok) {
        const payments = await payRes.json();
        const successPay = Array.isArray(payments) ? payments.find(p => p.payment_status === 'SUCCESS') : null;
        if (successPay?.cf_payment_id) {
          paymentId = String(successPay.cf_payment_id);
        }
      }
    } catch (_) {}

    // 3. Idempotency Check in wallet_transactions (prevent replay/duplicate credits)
    const { data: existingTx } = await supabase
      .from('wallet_transactions')
      .select('id, amount, status')
      .or(`reference_id.eq.${orderId},reference_id.eq.${paymentId}`)
      .maybeSingle();

    if (existingTx) {
      console.log(`[Cashfree] Order ${orderId} already credited previously.`);
      const { data: wallet } = await supabase
        .from('wallets')
        .select('balance')
        .eq('user_id', userId)
        .maybeSingle();

      return res.json({
        success: true,
        alreadyProcessed: true,
        message: 'Payment was already processed and credited.',
        newBalance: Number(wallet?.balance || 0),
        orderId,
        paymentId
      });
    }

    // 4. Atomic Wallet Crediting in Supabase
    let newBalance = 0;
    let creditSuccess = false;

    try {
      const { data: rpcRes, error: rpcErr } = await supabase.rpc('cashfree_deposit_atomic', {
        p_user_id: userId,
        p_amount: numAmount,
        p_order_id: orderId
      });

      if (!rpcErr && rpcRes && rpcRes.success) {
        creditSuccess = true;
        newBalance = rpcRes.new_balance;
        console.log(`[Supabase] RPC cashfree_deposit_atomic succeeded. New balance: ${newBalance}`);
      } else if (rpcErr) {
        console.warn(`[Supabase] RPC cashfree_deposit_atomic returned error:`, rpcErr.message);
      }
    } catch (rpcEx) {
      console.warn('[Supabase] RPC cashfree_deposit_atomic exception:', rpcEx.message);
    }

    // Fallback direct service-role update if RPC didn't complete
    if (!creditSuccess) {
      console.log('[Supabase] Applying direct wallet update with service_role for Cashfree deposit...');
      const { data: wallet } = await supabase
        .from('wallets')
        .select('balance')
        .eq('user_id', userId)
        .maybeSingle();

      const currentBalance = Number(wallet?.balance || 0);
      newBalance = currentBalance + numAmount;

      if (wallet) {
        await supabase
          .from('wallets')
          .update({ balance: newBalance, updated_at: new Date().toISOString() })
          .eq('user_id', userId);
      } else {
        await supabase
          .from('wallets')
          .insert([{ user_id: userId, balance: newBalance, winning_balance: 0 }]);
      }

      await supabase
        .from('wallet_transactions')
        .insert([{
          user_id: userId,
          type: 'DEPOSIT',
          amount: numAmount,
          status: 'SUCCESS',
          payment_gateway: 'CASHFREE',
          reference_id: orderId,
          notes: `Added ${numAmount} Coins via Cashfree (${orderId})`,
          created_at: new Date().toISOString()
        }]);

      console.log(`[Supabase] Direct Cashfree update succeeded. User: ${userId}, New balance: ${newBalance}`);
    }

    return res.json({
      success: true,
      message: 'Payment verified and wallet credited successfully.',
      orderId,
      paymentId,
      amountCredited: numAmount,
      newBalance
    });
  } catch (error) {
    console.error('[Cashfree] verify error:', error);
    return res.status(500).json({
      success: false,
      message: error.message || 'Payment verification or wallet credit failed'
    });
  }
});

/**
 * 3. CASHFREE: WEBHOOK HANDLER
 * POST /api/cashfree/webhook
 */
app.post('/api/cashfree/webhook', async (req, res) => {
  try {
    const eventType = req.body?.type;
    console.log(`[Cashfree Webhook] Received event: ${eventType}`);

    if (eventType === 'PAYMENT_SUCCESS_WEBHOOK') {
      const paymentData = req.body?.data?.payment;
      const orderData = req.body?.data?.order;
      const customerData = req.body?.data?.customer_details;

      const orderId = orderData?.order_id;
      const amount = Number(orderData?.order_amount || paymentData?.payment_amount || 0);
      const userId = customerData?.customer_id;

      if (orderId && userId && amount > 0) {
        console.log(`[Cashfree Webhook] Auto-crediting: order=${orderId}, user=${userId}, amount=${amount}`);

        const { data: existing } = await supabase
          .from('wallet_transactions')
          .select('id')
          .eq('reference_id', orderId)
          .maybeSingle();

        if (!existing) {
          await supabase.rpc('cashfree_deposit_atomic', {
            p_user_id: userId,
            p_amount: amount,
            p_order_id: orderId
          });
          console.log(`[Cashfree Webhook] Successfully credited order ${orderId}`);
        }
      }
    }

    return res.status(200).json({ status: 'ok' });
  } catch (err) {
    console.error('[Cashfree Webhook] Error:', err);
    return res.status(500).send('Webhook processing error');
  }
});

/**
 * ==============================================================================
 * RAZORPAY PAYMENT GATEWAY ENDPOINTS
 * ==============================================================================
 */

/**
 * 1. CREATE RAZORPAY ORDER
 * POST /api/payment/create-order
 * Request Body: { userId, amount, email, phone, name }
 */
app.post('/api/payment/create-order', async (req, res) => {
  try {
    const { userId, amount, email, phone, name } = req.body;

    if (!userId) {
      return res.status(400).json({ success: false, message: 'User ID is required' });
    }

    const numAmount = Number(amount);
    if (isNaN(numAmount) || numAmount < 10) {
      return res.status(400).json({ success: false, message: 'Minimum deposit amount is 10 Coins' });
    }

    const amountInPaise = Math.round(numAmount * 100);
    const receiptId = `rcpt_${String(userId).replace(/[^a-zA-Z0-9]/g, '').slice(0, 10)}_${Date.now().toString().slice(-8)}`;

    const options = {
      amount: amountInPaise,
      currency: 'INR',
      receipt: receiptId,
      notes: {
        userId: String(userId),
        amountInCoins: String(numAmount),
        email: email || '',
        phone: phone || '',
        name: name || ''
      }
    };

    console.log(`[Razorpay] Creating order for user: ${userId}, amount: ₹${numAmount} (${amountInPaise} paise)`);
    const order = await razorpay.orders.create(options);

    console.log(`[Razorpay] Order created successfully: ${order.id}`);
    return res.json({
      success: true,
      orderId: order.id,
      amount: order.amount,
      currency: order.currency,
      keyId: RAZORPAY_KEY_ID
    });
  } catch (error) {
    console.error('[Razorpay] create-order error:', error);
    return res.status(500).json({
      success: false,
      message: error?.error?.description || error.message || 'Failed to create Razorpay order'
    });
  }
});

/**
 * 2. VERIFY PAYMENT & ATOMIC WALLET CREDIT
 * POST /api/payment/verify
 * Request Body: { orderId, paymentId, signature, userId, amount }
 */
app.post('/api/payment/verify', async (req, res) => {
  try {
    const { orderId, paymentId, signature, userId, amount } = req.body;

    if (!orderId || !paymentId || !signature || !userId || !amount) {
      return res.status(400).json({
        success: false,
        message: 'Missing required parameters: orderId, paymentId, signature, userId, amount'
      });
    }

    const numAmount = Number(amount);
    if (isNaN(numAmount) || numAmount <= 0) {
      return res.status(400).json({ success: false, message: 'Invalid payment amount' });
    }

    console.log(`[Razorpay] Verifying payment: pid=${paymentId}, oid=${orderId}, uid=${userId}, amount=${numAmount}`);

    // A. Verify HMAC-SHA256 Signature
    const expectedSignature = crypto
      .createHmac('sha256', RAZORPAY_KEY_SECRET)
      .update(`${orderId}|${paymentId}`)
      .digest('hex');

    if (expectedSignature !== signature) {
      console.error(`[Razorpay] Signature mismatch! Expected: ${expectedSignature}, Received: ${signature}`);
      return res.status(400).json({
        success: false,
        message: 'Invalid payment signature. Verification failed.'
      });
    }
    console.log('[Razorpay] Signature verification passed!');

    // B. Verify payment state with Razorpay API
    try {
      const payment = await razorpay.payments.fetch(paymentId);
      console.log(`[Razorpay] Payment status from gateway: ${payment?.status}, amount: ${payment?.amount}`);
      if (!payment || (payment.status !== 'captured' && payment.status !== 'authorized')) {
        return res.status(400).json({
          success: false,
          message: `Payment is in invalid state: ${payment?.status || 'unknown'}`
        });
      }
    } catch (fetchErr) {
      console.warn('[Razorpay] Could not fetch payment status from API, proceeding with valid signature:', fetchErr.message);
    }

    // C. Idempotency Check in wallet_transactions
    const { data: existingTx } = await supabase
      .from('wallet_transactions')
      .select('id, amount, status')
      .eq('reference_id', paymentId)
      .maybeSingle();

    if (existingTx) {
      console.log(`[Razorpay] Payment ${paymentId} was already credited previously.`);
      const { data: wallet } = await supabase
        .from('wallets')
        .select('balance')
        .eq('user_id', userId)
        .maybeSingle();

      return res.json({
        success: true,
        alreadyProcessed: true,
        message: 'Payment was already processed and credited.',
        newBalance: wallet?.balance || 0
      });
    }

    // D. Atomic Wallet Crediting via RPC cashfree_deposit_atomic
    let newBalance = 0;
    let creditSuccess = false;

    try {
      const { data: rpcRes, error: rpcErr } = await supabase.rpc('cashfree_deposit_atomic', {
        p_user_id: userId,
        p_amount: numAmount,
        p_order_id: paymentId
      });

      if (!rpcErr && rpcRes && rpcRes.success) {
        creditSuccess = true;
        newBalance = rpcRes.new_balance;
        console.log(`[Supabase] RPC cashfree_deposit_atomic succeeded. New balance: ${newBalance}`);
      } else if (rpcErr) {
        console.warn(`[Supabase] RPC cashfree_deposit_atomic returned error:`, rpcErr.message);
      }
    } catch (rpcEx) {
      console.warn('[Supabase] RPC cashfree_deposit_atomic exception:', rpcEx.message);
    }

    // Fallback if RPC failed
    if (!creditSuccess) {
      console.log('[Supabase] Applying direct wallet update with service_role...');
      const { data: wallet, error: wErr } = await supabase
        .from('wallets')
        .select('balance')
        .eq('user_id', userId)
        .maybeSingle();

      const currentBalance = Number(wallet?.balance || 0);
      newBalance = currentBalance + numAmount;

      if (wallet) {
        await supabase
          .from('wallets')
          .update({ balance: newBalance, updated_at: new Date().toISOString() })
          .eq('user_id', userId);
      } else {
        await supabase
          .from('wallets')
          .insert([{ user_id: userId, balance: newBalance, winning_balance: 0 }]);
      }

      // Insert into wallet_transactions
      await supabase
        .from('wallet_transactions')
        .insert([{
          user_id: userId,
          type: 'DEPOSIT',
          amount: numAmount,
          status: 'SUCCESS',
          payment_gateway: 'RAZORPAY',
          reference_id: paymentId,
          notes: `Added ${numAmount} Coins via Razorpay (${paymentId})`,
          created_at: new Date().toISOString()
        }]);

      console.log(`[Supabase] Direct update succeeded. User: ${userId}, New balance: ${newBalance}`);
    }

    return res.json({
      success: true,
      message: 'Payment verified and wallet credited successfully.',
      paymentId,
      orderId,
      amountCredited: numAmount,
      newBalance
    });
  } catch (error) {
    console.error('[Razorpay] verify error:', error);
    return res.status(500).json({
      success: false,
      message: error.message || 'Payment verification or wallet credit failed'
    });
  }
});

/**
 * 3. RAZORPAY WEBHOOK HANDLER
 * POST /api/payment/webhook
 */
app.post('/api/payment/webhook', async (req, res) => {
  try {
    const webhookSignature = req.headers['x-razorpay-signature'];
    const webhookSecret = process.env.RAZORPAY_WEBHOOK_SECRET || RAZORPAY_KEY_SECRET;

    if (webhookSignature) {
      const shasum = crypto.createHmac('sha256', webhookSecret);
      shasum.update(JSON.stringify(req.body));
      const digest = shasum.digest('hex');

      if (digest !== webhookSignature) {
        console.warn('[Webhook] Invalid webhook signature');
        return res.status(400).send('Invalid signature');
      }
    }

    const event = req.body?.event;
    console.log(`[Webhook] Received Razorpay event: ${event}`);

    if (event === 'payment.captured') {
      const payment = req.body?.payload?.payment?.entity;
      if (payment) {
        const paymentId = payment.id;
        const amount = payment.amount / 100;
        const userId = payment.notes?.userId;

        if (userId && paymentId) {
          console.log(`[Webhook] Auto-crediting payment: pid=${paymentId}, uid=${userId}, amount=${amount}`);

          const { data: existing } = await supabase
            .from('wallet_transactions')
            .select('id')
            .eq('reference_id', paymentId)
            .maybeSingle();

          if (!existing) {
            await supabase.rpc('cashfree_deposit_atomic', {
              p_user_id: userId,
              p_amount: amount,
              p_order_id: paymentId
            });
            console.log(`[Webhook] Successfully processed payment ${paymentId}`);
          }
        }
      }
    }

    res.status(200).json({ status: 'ok' });
  } catch (err) {
    console.error('[Webhook] Error handling webhook:', err);
    res.status(500).send('Webhook processing error');
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`====================================================`);
  console.log(`  BLUELOCK ESPORTS PAYMENT BACKEND STARTED`);
  console.log(`  Listening on port: ${PORT}`);
  console.log(`  Razorpay Key ID: ${RAZORPAY_KEY_ID}`);
  console.log(`====================================================`);
});
