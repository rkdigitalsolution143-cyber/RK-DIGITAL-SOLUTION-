# RK Digital Solution — Backend Starter Kit

Ye ek **basic backend** hai jo `app.html` ke localStorage system ko replace karne ke liye banaya gaya hai. Isse aapka data **real database** mein save hoga, jo har device se access ho sakega.

## Kya Kya Hai Isme

- ✅ Real database (SQLite — file-based, free, no setup needed)
- ✅ Secure login (bcrypt password hashing + JWT tokens)
- ✅ Agent registration API
- ✅ Transaction recording API
- ✅ Admin: agent management, wallet add/deduct, notices
- ✅ Ready to deploy on free hosting (Render/Railway)

## Setup (Local Testing)

```bash
cd backend-starter
npm install
cp .env.example .env
# .env file mein JWT_SECRET change kar do (koi bhi random long text)
npm start
```

Server `http://localhost:3000` pe chalega.

## Free Deployment (Step by Step)

### Option 1: Render.com (Recommended, Free)
1. https://render.com pe account banao (GitHub se login)
2. Ye `backend-starter` folder ko GitHub repo mein push karo
3. Render dashboard mein "New Web Service" → apna repo select karo
4. Build Command: `npm install`
5. Start Command: `npm start`
6. Environment Variables mein `.env.example` ke values add karo (JWT_SECRET zaroor change karo)
7. Deploy hone ke baad aapko ek URL milega jaise: `https://rk-digital-backend.onrender.com`

### Option 2: Railway.app
1. https://railway.app pe GitHub se login
2. "New Project" → "Deploy from GitHub repo"
3. Apna backend-starter folder select karo
4. Automatically deploy ho jayega, URL mil jayega

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/login` | Login (id, password) → returns JWT token |
| POST | `/api/register` | New agent register |
| GET | `/api/profile` | Get logged-in agent profile (needs token) |
| POST | `/api/change-password` | Change password |
| POST | `/api/transactions` | Record a transaction |
| GET | `/api/transactions` | Get transaction history |
| GET | `/api/admin/agents` | (Admin only) List all agents |
| POST | `/api/admin/agents/:id/wallet` | (Admin only) Add/deduct wallet balance |
| POST | `/api/admin/agents/:id/status` | (Admin only) Block/unblock agent |
| POST | `/api/admin/notices` | (Admin only) Post a notice |
| GET | `/api/notices` | Get latest notices |

All protected endpoints need header: `Authorization: Bearer <token>`

## app.html Ko Connect Karna

Abhi `app.html` localStorage use karta hai. Isse backend se connect karne ke liye:

1. Login function mein `fetch('https://your-backend-url.com/api/login', {method:'POST', body: JSON.stringify({id, password})})` call karo
2. Response se mila `token` ko `localStorage` mein save karo
3. Har API call mein header add karo: `Authorization: Bearer ' + token`
4. `AGENTS`, `TRANSACTIONS` jaise local arrays ki jagah API se data fetch karo

**Note:** Ye migration thoda technical hai. Agar chaho to step-by-step iska bhi code likh sakta hoon.

## Default Admin Login

- ID: `RKADMIN`
- Password: `admin@rk123`

⚠️ **Production mein deploy karne se pehle ye password zaroor change karo!**

## AEPS/DMT/Recharge Real API Ke Liye

Ye backend sirf agent/wallet/transaction database manage karta hai. Real payment processing ke liye aapko ek **AEPS Master Distributor** se API lena hoga:

- **PaySprint** — https://paysprint.in
- **Eko India** — https://eko.in
- **Instantpay** — https://instantpay.in
- **RapiPay** — https://rapipay.com

Unka API documentation milega, jisko `server.js` mein naye routes add karke integrate kar sakte ho (e.g. `/api/aeps/withdrawal`).
