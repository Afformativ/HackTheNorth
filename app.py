import os
import re
from datetime import datetime, timedelta
from bson import ObjectId
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity
)
from pymongo import MongoClient, ASCENDING, DESCENDING

# XRPL
from xrpl_client import create_wallet as xrpl_create_wallet, create_escrow, finish_escrow
from xrpl.wallet import Wallet
from xrpl.clients import JsonRpcClient
from xrpl.models.requests import AccountInfo, AccountLines, Tx
from xrpl.models.transactions import Payment, TrustSet
from xrpl.transaction import submit_and_wait
from xrpl.models.amounts import IssuedCurrencyAmount
from xrpl.models.transactions import TrustSetFlag

# ---------------- XRPL CONFIG ----------------
CLIENT = JsonRpcClient("https://s.altnet.rippletest.net:51234")
ISSUER_ADDRESS = "rEBQEFvhgZKEbUMSFcwe5SM7FyEDN26zRL"
ISSUER_SEED = "sEd7puA5JQz7znDjUHPZMLVJhzv8pen"  # testnet only

# Custodial hold wallet for RLUSD (IOU)
ESCROW_HOT_SEED = os.environ.get("ESCROW_HOT_SEED", ISSUER_SEED)
ESCROW_HOT_WALLET = Wallet.from_seed(ESCROW_HOT_SEED)
ESCROW_HOT_ADDR = ESCROW_HOT_WALLET.classic_address

# ---------------- DEFAULT TOPICS ----------------
DEFAULT_TOPICS = [
    "Cryptography","Zero-Knowledge","Smart Contracts","XRPL",
    "DeFi","NFTs","Consensus","Security Audit",
    "Wallet Development","APIs & SDKs",
    "Front-end (React)","Back-end (Flask)",
    "Performance","Gas Optimization",
    "Rust","Go","TypeScript","Python",
    "Data Structures","Algorithms","Mathematics",
    "UX/UI","DevOps","Testing/QA"
]

# ---------------- FLASK ----------------
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=False)
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "dev-insecure")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=24)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=14)
jwt = JWTManager(app)

# ---------------- MONGO ----------------
MONGODB_URI = os.environ.get("MONGODB_URI", "mongodb://127.0.0.1:27017")
mongo = MongoClient(MONGODB_URI)
db = mongo["xrpl_aid"]
users = db["users"]
wallets = db["wallets"]
tasks = db["tasks"]
topics_col = db["topics"]
escrows = db["escrows"]

users.create_index([("email", ASCENDING)], unique=True)
wallets.create_index([("address", ASCENDING)], unique=True)
wallets.create_index([("user_id", ASCENDING)])
tasks.create_index([("created_by", ASCENDING)])
tasks.create_index([("assigned_to", ASCENDING)])
tasks.create_index([("status", ASCENDING)])
tasks.create_index([("topic", ASCENDING)])
tasks.create_index([("created_at", DESCENDING)])
topics_col.create_index([("name", ASCENDING)], unique=True)
escrows.create_index([("task_id", ASCENDING)])
escrows.create_index([("type", ASCENDING)])
escrows.create_index([("status", ASCENDING)])

# ---------------- HELPERS ----------------
def now_utc(): return datetime.utcnow()
TOPIC_RE = re.compile(r"^[\w\s\-\.\&\+\/]{2,40}$")

def normalize_topic(name: str) -> str:
    t = (name or "").strip()
    t = re.sub(r"\s+", " ", t)
    return t

def get_all_topics():
    names = set(DEFAULT_TOPICS)
    for doc in topics_col.find({}, {"name": 1}):
        if doc.get("name"):
            names.add(doc["name"])
    return sorted(names, key=lambda x: x.lower())

def topic_exists(name: str) -> bool:
    t = normalize_topic(name)
    if not t: return False
    if t in DEFAULT_TOPICS: return True
    return topics_col.count_documents({"name": t}) > 0

def ensure_topic_exists(name: str, creator_oid=None):
    t = normalize_topic(name)
    if not t or topic_exists(t): return t
    if not TOPIC_RE.match(t):
        raise ValueError("Topic must be 2–40 chars (letters, numbers, space, - . & + /)")
    topics_col.insert_one({"name": t, "created_by": creator_oid, "created_at": now_utc()})
    return t

def get_user_email(oid):
    try:
        u = users.find_one({"_id": oid}, {"email": 1})
        return u["email"] if u else None
    except Exception:
        return None

def allow_rippling(wallet, peer_address):
    trust_set = TrustSet(
        account=wallet.classic_address,
        limit_amount=IssuedCurrencyAmount(currency="USD", issuer=peer_address, value="1000000"),
        flags=TrustSetFlag.TF_CLEAR_NO_RIPPLE
    )
    return submit_and_wait(trust_set, CLIENT, wallet)

def get_xrp_balance(address):
    try:
        req = AccountInfo(account=address, ledger_index="validated", strict=True)
        response = CLIENT.request(req)
        if "account_data" not in response.result:
            return 0.0
        balance_drops = int(response.result["account_data"]["Balance"])
        return balance_drops / 1_000_000
    except Exception:
        return 0.0

def get_rlusd_balance(address):
    try:
        req = AccountLines(account=address, ledger_index="validated", peer=ISSUER_ADDRESS)
        response = CLIENT.request(req)
        for line in response.result.get("lines", []):
            if line["currency"] == "USD":
                return float(line["balance"])
        return 0.0
    except Exception:
        return 0.0

def ensure_trustline(address, seed, issuer=ISSUER_ADDRESS, limit="1000000"):
    wallet = Wallet.from_seed(seed)
    trust_tx = TrustSet(account=address, limit_amount=IssuedCurrencyAmount(currency="USD", issuer=issuer, value=limit))
    res = submit_and_wait(trust_tx, CLIENT, wallet)
    try:
        allow_rippling(wallet, issuer)
    except Exception:
        pass
    return res

def rl_usd_payment(sender_seed, dest_address, amount):
    sender_wallet = Wallet.from_seed(sender_seed)
    iou = IssuedCurrencyAmount(currency="USD", issuer=ISSUER_ADDRESS, value=str(amount))
    tx = Payment(account=sender_wallet.classic_address, destination=dest_address, amount=iou, send_max=iou)
    return submit_and_wait(tx, CLIENT, sender_wallet)

def user_owns_wallet(uid, addr):
    return wallets.find_one({"address": addr, "user_id": ObjectId(uid)})

def compute_wallet_held(uid, address):
    q = {"created_by": ObjectId(uid), "created_wallet": address,
         "status": {"$in": ["open", "assigned", "under_review", "changes_requested"]}}
    total = 0.0
    for t in tasks.find(q):
        total += float(t.get("price", 0))
    return total

def get_solver_stats_for_user_ids(uid_list):
    if not uid_list: return {}
    ids = [ObjectId(u) for u in uid_list]
    pipeline = [
        {"$match": {"assigned_to": {"$in": ids}, "status": "paid"}},
        {"$group": {"_id": {"uid": "$assigned_to", "topic": "$topic"}, "count": {"$sum": 1}}}
    ]
    out = {}
    for row in tasks.aggregate(pipeline):
        uid = str(row["_id"]["uid"])
        topic = row["_id"]["topic"] or "General"
        cnt = int(row["count"])
        if uid not in out:
            out[uid] = {"total": 0, "by_topic": {}}
        out[uid]["total"] += cnt
        out[uid]["by_topic"][topic] = out[uid]["by_topic"].get(topic, 0) + cnt
    return out

def sanitize_candidates_for_viewer(t, viewer_id):
    candidates = t.get("candidates", [])
    if viewer_id and t.get("created_by") and str(t["created_by"]) == str(viewer_id):
        uid_list = [str(c["user_id"]) for c in candidates]
        stats_map = get_solver_stats_for_user_ids(uid_list)
        return [
            {
                "user_id": str(c["user_id"]),
                "email": c.get("email"),
                "wallet": c.get("wallet"),
                "note": c.get("note"),
                "applied_at": c.get("applied_at"),
                "stats": {
                    "solved_total": stats_map.get(str(c["user_id"]), {}).get("total", 0),
                    "topics": [{"topic": k, "count": v} for k, v in sorted(stats_map.get(str(c["user_id"]), {}).get("by_topic", {}).items(), key=lambda kv: (-kv[1], kv[0].lower()))]
                }
            } for c in candidates
        ]
    if not viewer_id: return []
    mine = [c for c in candidates if str(c["user_id"]) == str(viewer_id)]
    return [
        {
            "user_id": str(c["user_id"]),
            "email": c.get("email"),
            "wallet": c.get("wallet"),
            "note": c.get("note"),
            "applied_at": c.get("applied_at")
        } for c in mine
    ]

def sanitize_history_for_viewer(t, viewer_id):
    allowed = viewer_id and (str(t.get("created_by")) == str(viewer_id) or str(t.get("assigned_to")) == str(viewer_id))
    if not allowed:
        return [], []
    subs = [{
        "version": s["version"],
        "answer": s["answer"],
        "wallet": s.get("wallet"),
        "solver_id": str(s.get("solver_id")) if s.get("solver_id") else None,
        "submitted_at": s.get("submitted_at")
    } for s in t.get("submissions", [])]
    revs = [{
        "version": r["version"],
        "comments": r["comments"],
        "reviewer_id": str(r.get("reviewer_id")) if r.get("reviewer_id") else None,
        "created_at": r.get("created_at"),
        "type": r.get("type", "changes_requested")
    } for r in t.get("reviews", [])]
    return subs, revs

def task_public_view(t, viewer_id=None):
    created_by = t.get("created_by")
    out = {
        "_id": str(t["_id"]),
        "title": t.get("title"),
        "description": t.get("description"),
        "price": t.get("price"),
        "currency": t.get("currency", "RLUSD"),
        "escrow_type": t.get("escrow_type", "rlusd"),
        "topic": t.get("topic") or "General",
        "status": t.get("status", "open"),
        "created_by": str(created_by) if created_by else None,
        "created_by_email": get_user_email(created_by) if created_by else None,
        "created_wallet": t.get("created_wallet"),
        "issuer_address": t.get("issuer_address", ISSUER_ADDRESS),
        "created_at": t.get("created_at"),
        "updated_at": t.get("updated_at"),
        "assigned_to": str(t.get("assigned_to")) if t.get("assigned_to") else None,
        "assigned_wallet": t.get("assigned_wallet"),
        "assigned_at": t.get("assigned_at"),
        "hold": {
            "status": t.get("hold_status"),
            "amount": t.get("hold_amount"),
            "tx_hash": t.get("hold_tx_hash"),
            "escrow_sequence": t.get("escrow_sequence")
        },
        "answer": None
    }
    # AI fields
    out["ai_review_enabled"] = t.get("ai_review_enabled", False)
    out["ai_last_verdict"] = t.get("ai_last_verdict")
    out["ai_last_reason"] = t.get("ai_last_reason")
    out["ai_passed_at"] = t.get("ai_passed_at")

    if viewer_id and (str(created_by) == str(viewer_id) or str(t.get("assigned_to")) == str(viewer_id)):
        if t.get("submissions"):
            out["answer"] = t["submissions"][-1].get("answer")

    out["candidates"] = sanitize_candidates_for_viewer(t, viewer_id)
    subs, revs = sanitize_history_for_viewer(t, viewer_id)
    out["submissions"] = subs
    out["reviews"] = revs

    if viewer_id and str(created_by) == str(viewer_id) and t.get("assigned_to"):
        paid_count = tasks.count_documents({"assigned_to": t["assigned_to"], "status": "paid"})
        out["solver_stats"] = {"paid_count": int(paid_count), "solver_id": str(t["assigned_to"])}

    out["paid_tx_hash"] = t.get("paid_tx_hash")
    out["paid_at"] = t.get("paid_at")
    out["solved"] = (t.get("status") == "paid")
    return out

# ---------------- AUTH ----------------
@app.route("/auth/register", methods=["POST", "OPTIONS"])
def auth_register():
    if request.method == "OPTIONS": return ("", 200)
    data = request.json or {}
    email = (data.get("email") or "").strip().lower()
    password = (data.get("password") or "").strip()
    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400
    if users.find_one({"email": email}):
        return jsonify({"error": "Email already registered"}), 409
    # Explicitly use pbkdf2 to avoid environments where hashlib.scrypt isn't available
    pw_hash = generate_password_hash(password, method="pbkdf2:sha256", salt_length=16)
    res = users.insert_one({"email": email, "password_hash": pw_hash, "expertise": [], "custom_topics": [], "created_at": now_utc()})
    uid = str(res.inserted_id)
    access = create_access_token(identity=uid)
    refresh = create_refresh_token(identity=uid)
    return jsonify({"access_token": access, "refresh_token": refresh, "user": {"_id": uid, "email": email, "expertise": []}})

@app.route("/auth/login", methods=["POST", "OPTIONS"])
def auth_login():
    if request.method == "OPTIONS": return ("", 200)
    data = request.json or {}
    email = (data.get("email") or "").strip().lower()
    password = (data.get("password") or "").strip()
    u = users.find_one({"email": email})
    if not u or not check_password_hash(u["password_hash"], password):
        return jsonify({"error": "Invalid credentials"}), 401
    uid = str(u["_id"])
    access = create_access_token(identity=uid)
    refresh = create_refresh_token(identity=uid)
    return jsonify({"access_token": access, "refresh_token": refresh, "user": {"_id": uid, "email": u["email"], "expertise": u.get("expertise", [])}})

@app.route("/auth/refresh", methods=["POST", "OPTIONS"])
@jwt_required(refresh=True)
def auth_refresh():
    if request.method == "OPTIONS": return ("", 200)
    uid = get_jwt_identity()
    return jsonify({"access_token": create_access_token(identity=uid)})

@app.route("/me", methods=["GET"])
@jwt_required()
def me():
    uid = get_jwt_identity()
    u = users.find_one({"_id": ObjectId(uid)})
    return jsonify({"user": {"_id": str(u["_id"]), "email": u["email"], "expertise": u.get("expertise", []), "custom_topics": u.get("custom_topics", []),"phone": u.get("phone", "")}})

@app.route("/me/profile", methods=["POST", "OPTIONS"])
@jwt_required()
def me_profile():
    if request.method == "OPTIONS": 
        return ("", 200)
    uid = get_jwt_identity()
    data = request.json or {}
    phone = (data.get("phone") or "").strip()
    if phone and not re.match(r"^[\d\+\-\s\(\)]{6,20}$", phone):
        return jsonify({"error": "bad phone format"}), 400
    users.update_one({"_id": ObjectId(uid)}, {"$set": {"phone": phone, "updated_at": datetime.utcnow()}})
    u = users.find_one({"_id": ObjectId(uid)})
    return jsonify({"ok": True, "user": {"_id": uid, "email": u["email"], "phone": u.get("phone", ""), "expertise": u.get("expertise", [])}})

# ---------------- PERSONAL TOPICS (for users) ----------------
@app.route("/me/topics", methods=["GET","POST","OPTIONS"])
@jwt_required()
def me_topics():
    if request.method == "OPTIONS": return ("", 200)
    uid = get_jwt_identity()
    if request.method == "GET":
        u = users.find_one({"_id": ObjectId(uid)}, {"custom_topics": 1})
        return jsonify({"topics": u.get("custom_topics", [])})
    data = request.json or {}
    name = normalize_topic(data.get("name") or "")
    if not name: return jsonify({"error":"name required"}), 400
    if not TOPIC_RE.match(name): return jsonify({"error":"Topic must be 2–40 chars (letters, numbers, space, - . & + /)"}), 400
    # store globally as well so it appears for task creation
    if not topic_exists(name):
        topics_col.insert_one({"name": name, "created_by": ObjectId(uid), "created_at": now_utc()})
    users.update_one({"_id": ObjectId(uid)}, {"$addToSet": {"custom_topics": name}})
    u = users.find_one({"_id": ObjectId(uid)}, {"custom_topics": 1})
    return jsonify({"ok": True, "topics": u.get("custom_topics", [])})

# ---------------- TOPICS (global) & EXPERTISE ----------------
@app.route("/topics", methods=["GET", "POST", "OPTIONS"])
@jwt_required(optional=True)
def topics_api():
    if request.method == "OPTIONS": return ("", 200)
    if request.method == "GET":
        return jsonify({"topics": get_all_topics()})
    uid = get_jwt_identity()
    if not uid: return jsonify({"error":"auth required"}), 401
    data = request.json or {}
    name = normalize_topic(data.get("name") or "")
    if not name: return jsonify({"error":"name required"}), 400
    if not TOPIC_RE.match(name): return jsonify({"error":"Topic must be 2–40 chars (letters, numbers, space, - . & + /)"}), 400
    if not topic_exists(name):
        topics_col.insert_one({"name": name, "created_by": ObjectId(uid), "created_at": now_utc()})
    users.update_one({"_id": ObjectId(uid)}, {"$addToSet": {"custom_topics": name}})
    return jsonify({"ok": True, "topics": get_all_topics()})

@app.route("/me/expertise", methods=["GET","POST","OPTIONS"])
@jwt_required()
def me_expertise():
    if request.method == "OPTIONS": return ("", 200)
    uid = get_jwt_identity()
    if request.method == "GET":
        u = users.find_one({"_id": ObjectId(uid)})
        return jsonify({"expertise": u.get("expertise", []), "custom_topics": u.get("custom_topics", [])})
    data = request.json or {}
    exp = data.get("expertise", [])
    if not isinstance(exp, list): return jsonify({"error":"expertise must be a list"}), 400
    all_topics = set(get_all_topics())
    norm = []
    for t in exp:
        t2 = normalize_topic(t)
        if not t2: continue
        if t2 not in all_topics:
            ensure_topic_exists(t2, ObjectId(uid))
            all_topics.add(t2)
        if t2 not in norm:
            norm.append(t2)
    if len(norm) < 3 or len(norm) > 5: return jsonify({"error":"choose between 3 and 5 topics"}), 400
    users.update_one({"_id": ObjectId(uid)}, {"$set": {"expertise": norm}})
    return jsonify({"ok": True, "expertise": norm})

# ---------------- BASIC ----------------
@app.route("/")
def index():
  return "✅ XRPL Aid Backend is Running!"

# ---------------- WALLETS ----------------
@app.route("/my/add_wallet", methods=["POST", "OPTIONS"])
@jwt_required()
def my_add_wallet():
    if request.method == "OPTIONS": return ("", 200)
    uid = get_jwt_identity()
    w = xrpl_create_wallet()
    trust_ok = True
    try:
        ensure_trustline(w.classic_address, w.seed, ISSUER_ADDRESS)
    except Exception:
        trust_ok = False
    wallets.insert_one({
        "address": w.classic_address,
        "seed": w.seed,  # testnet only
        "user_id": ObjectId(uid),
        "trustline_rlusd": trust_ok,
        "created_at": now_utc(),
        "updated_at": now_utc()
    })
    return jsonify({"address": w.classic_address})

@app.route("/my/wallets", methods=["GET"])
@jwt_required()
def my_wallets():
    uid = get_jwt_identity()
    out = []
    cur = wallets.find({"user_id": ObjectId(uid)}).sort("created_at", DESCENDING)
    for w in cur:
        xb = get_xrp_balance(w["address"])
        rb = get_rlusd_balance(w["address"])
        wallets.update_one({"_id": w["_id"]}, {"$set": {"xrp_balance": xb, "rlusd_balance": rb, "updated_at": now_utc()}})
        held = compute_wallet_held(uid, w["address"])
        out.append({
            "address": w["address"],
            "user_id": str(w["user_id"]),
            "trustline_rlusd": bool(w.get("trustline_rlusd", False)),
            "created_at": w.get("created_at"),
            "xrp_balance": xb,
            "rlusd_balance": rb,
            "held_rlusd": held
        })
    return jsonify({"wallets": out})

@app.route("/my/delete_wallet", methods=["POST", "OPTIONS"])
@jwt_required()
def my_delete_wallet():
    if request.method == "OPTIONS": return ("", 200)
    uid = get_jwt_identity()
    data = request.json or {}
    address = (data.get("address") or "").trim()
    if not address: return jsonify({"error":"address required"}), 400
    wdoc = user_owns_wallet(uid, address)
    if not wdoc: return jsonify({"error":"wallet not found or not owned"}), 404
    held = compute_wallet_held(uid, address)
    if held > 0: return jsonify({"error": f"Cannot delete; {held} RLUSD held by tasks"}), 400
    wallets.delete_one({"_id": wdoc["_id"]})
    return jsonify({"ok": True})

# ---------------- DEV FUND RLUSD ----------------
@app.route("/send_rlusd", methods=["POST", "OPTIONS"])
def send_rlusd():
    if request.method == "OPTIONS": return ("", 200)
    data = request.json or {}
    destination = data.get("destination")
    amount = data.get("amount")
    if not destination or not amount:
        return jsonify({"error":"Missing destination or amount"}), 400
    issuer_wallet = Wallet.from_seed(ISSUER_SEED)
    try:
        tx = Payment(
            account=issuer_wallet.classic_address,
            destination=destination,
            amount=IssuedCurrencyAmount(currency="USD", issuer=issuer_wallet.classic_address, value=str(amount))
        )
        response = submit_and_wait(tx, CLIENT, issuer_wallet)
        try:
            allow_rippling(issuer_wallet, destination)
        except Exception:
            pass
        return jsonify({"success": True, "tx_hash": response.result["hash"], "destination": destination, "amount": amount})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---------------- XRPL TX LOOKUP ----------------
@app.route("/tx/<tx_hash>", methods=["GET", "OPTIONS"])
def tx_lookup(tx_hash):
    if request.method == "OPTIONS": return ("", 200)
    try:
        req = Tx(transaction=tx_hash, binary=False)
        resp = CLIENT.request(req)
        return jsonify(resp.result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---------------- TASKS ----------------
@app.route("/tasks", methods=["POST", "OPTIONS"])
@jwt_required()
def create_task():
    if request.method == "OPTIONS": return ("", 200)
    uid = get_jwt_identity()
    data = request.json or {}
    title = (data.get("title") or "").strip() or "Untitled Task"
    description = (data.get("description") or "").strip()
    price = float(data.get("price") or 0)
    from_address = (data.get("from_address") or "").strip()
    topic = normalize_topic(data.get("topic") or "")
    currency = (data.get("currency") or "RLUSD").upper()
    if currency not in ("RLUSD", "XRP"): currency = "RLUSD"
    ai_review_enabled = bool(data.get("ai_review_enabled", False))

    if not description or price <= 0 or not from_address:
        return jsonify({"error":"description, price>0 and from_address required"}), 400

    try:
        topic = ensure_topic_exists(topic, ObjectId(uid))
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400

    wdoc = user_owns_wallet(uid, from_address)
    if not wdoc: return jsonify({"error":"from_address not owned by user"}), 403

    hold_status = None
    hold_tx = None
    escrow_seq = None

    if currency == "RLUSD":
        try: ensure_trustline(from_address, wdoc["seed"], ISSUER_ADDRESS)
        except Exception: pass
        bal = get_rlusd_balance(from_address)
        if bal < price: return jsonify({"error": f"Insufficient RLUSD balance ({bal})"}), 400
        try:
            tx = rl_usd_payment(wdoc["seed"], ESCROW_HOT_ADDR, price)
            hold_tx = tx.result.get("hash")
            hold_status = "held"
            escrows.insert_one({
                "type": "rlusd_hold",
                "task_id": None,
                "creator_id": ObjectId(uid),
                "from_address": from_address,
                "amount_rlusd": price,
                "hold_tx_hash": hold_tx,
                "status": "held",
                "created_at": now_utc()
            })
        except Exception as e:
            return jsonify({"error": f"Hold transfer failed: {str(e)}"}), 500
    else:
        hold_status = "pending_escrow"

    tdoc = {
        "title": title,
        "description": description,
        "price": price,
        "currency": currency,
        "escrow_type": "rlusd" if currency == "RLUSD" else "xrp",
        "topic": topic,
        "status": "open",
        "created_by": ObjectId(uid),
        "created_wallet": from_address,
        "issuer_address": ISSUER_ADDRESS,
        "created_at": now_utc(),
        "updated_at": now_utc(),
        "hold_status": hold_status,
        "hold_amount": price,
        "hold_tx_hash": hold_tx,
        "escrow_sequence": escrow_seq,
        "candidates": [],
        "assigned_to": None,
        "assigned_wallet": None,
        "assigned_at": None,
        "submissions": [],
        "reviews": [],
        "paid_tx_hash": None,
        "paid_at": None,
        # AI review fields
        "ai_review_enabled": ai_review_enabled,
        "ai_last_verdict": None,
        "ai_last_reason": None,
        "ai_passed_at": None,
    }
    res = tasks.insert_one(tdoc)
    tdoc["_id"] = res.inserted_id

    if currency == "RLUSD" and hold_tx:
        escrows.update_one(
            {"hold_tx_hash": hold_tx, "type":"rlusd_hold", "status":"held", "task_id": None},
            {"$set": {"task_id": tdoc["_id"]}}
        )

    return jsonify({"task": task_public_view(tdoc, viewer_id=uid)})

@app.route("/tasks", methods=["GET"])
@jwt_required(optional=True)
def list_tasks():
    viewer_id = get_jwt_identity()
    topic = request.args.get("topic")
    archived = (request.args.get("archived") or "").lower() in ("1","true","yes")

    if archived:
        if not viewer_id:
            return jsonify({"tasks": []})
        q = {"status": "paid", "$or": [{"created_by": ObjectId(viewer_id)}, {"assigned_to": ObjectId(viewer_id)}]}
    else:
        q = {"status": "open"} if not viewer_id else {
            "$or": [
                {"status": "open"},
                {"created_by": ObjectId(viewer_id), "status": {"$ne": "paid"}},
                {"assigned_to": ObjectId(viewer_id), "status": {"$ne": "paid"}},
            ]
        }

    if topic:
        q["topic"] = normalize_topic(topic)

    cur = tasks.find(q).sort("created_at", -1)
    return jsonify({"tasks": [task_public_view(x, viewer_id=viewer_id) for x in cur]})

@app.route("/tasks/<task_id>", methods=["GET"])
@jwt_required(optional=True)
def get_task(task_id):
    viewer_id = get_jwt_identity()
    try:
        t = tasks.find_one({"_id": ObjectId(task_id)})
        if not t: return jsonify({"error":"Task not found"}), 404
        if t.get("status") in ["assigned","under_review","changes_requested","paid"]:
            if not viewer_id or (str(t.get("created_by")) != str(viewer_id) and str(t.get("assigned_to")) != str(viewer_id)):
                return jsonify({"error":"Not authorized"}), 403
        return jsonify({"task": task_public_view(t, viewer_id=viewer_id)})
    except Exception:
        return jsonify({"error":"Bad task id"}), 400

@app.route("/tasks/<task_id>", methods=["DELETE", "OPTIONS"])
@jwt_required()
def delete_task(task_id):
    if request.method == "OPTIONS": return ("", 200)
    uid = get_jwt_identity()
    try: _id = ObjectId(task_id)
    except Exception: return jsonify({"error": "Bad task id"}), 400

    t = tasks.find_one({"_id": _id})
    if not t: return jsonify({"error": "Task not found"}), 404
    if str(t.get("created_by")) != str(uid):
        return jsonify({"error": "Only the creator can delete"}), 403
    if t.get("status") != "open" or t.get("assigned_to"):
        return jsonify({"error": "Only unassigned OPEN tasks can be deleted"}), 400

    currency = (t.get("currency") or "RLUSD").upper()
    price = float(t.get("price") or 0)
    if currency == "RLUSD" and price > 0 and (t.get("hold_status") in ("held", "iou_hold")):
        try:
            tx = rl_usd_payment(ESCROW_HOT_SEED, t.get("created_wallet"), price)
            refund_hash = tx.result.get("hash")
            escrows.update_one(
                {"task_id": _id, "type": "rlusd_hold", "status": "held"},
                {"$set": {"status": "refunded", "refund_tx_hash": refund_hash, "refunded_at": datetime.utcnow()}}
            )
        except Exception as e:
            return jsonify({"error": f"Refund failed: {str(e)}"}), 500

    tasks.delete_one({"_id": _id})
    return jsonify({"ok": True})

@app.route("/tasks/<task_id>/apply", methods=["POST", "OPTIONS"])
@jwt_required()
def apply_task(task_id):
    if request.method == "OPTIONS": return ("", 200)
    uid = get_jwt_identity()
    data = request.json or {}
    wallet_addr = (data.get("wallet") or "").strip()
    note = (data.get("note") or "").strip()
    try: _id = ObjectId(task_id)
    except Exception: return jsonify({"error":"Bad task id"}), 400
    t = tasks.find_one({"_id": _id})
    if not t: return jsonify({"error":"Task not found"}), 404
    if t.get("created_by") and str(t["created_by"]) == uid:
        return jsonify({"error":"Creator cannot apply"}), 403
    if t.get("status") != "open":
        return jsonify({"error":"Task not open"}), 400
    if not wallet_addr: return jsonify({"error":"wallet required"}), 400
    wdoc = wallets.find_one({"address": wallet_addr, "user_id": ObjectId(uid)})
    if not wdoc: return jsonify({"error":"wallet not owned by user"}), 403

    candidates = t.get("candidates", [])
    found = False
    for c in candidates:
        if str(c["user_id"]) == uid:
            c["wallet"] = wallet_addr
            c["note"] = note
            c["applied_at"] = now_utc()
            found = True
            break
    if not found:
        candidates.append({
            "user_id": ObjectId(uid),
            "email": get_user_email(ObjectId(uid)),
            "wallet": wallet_addr,
            "note": note,
            "applied_at": now_utc()
        })
    tasks.update_one({"_id": _id}, {"$set": {"candidates": candidates, "updated_at": now_utc()}})
    return jsonify({"ok": True})

@app.route("/tasks/<task_id>/assign", methods=["POST"])
@jwt_required()
def assign_task(task_id):
    uid = get_jwt_identity()
    try:
        _id = ObjectId(task_id)
    except Exception:
        return jsonify({"error": "Bad task id"}), 400

    data = request.json or {}
    cand_uid_str = data.get("candidate_user_id")
    cand_wallet_addr = (data.get("candidate_wallet_address") or "").strip()
    if not cand_uid_str or not cand_wallet_addr:
        return jsonify({"error": "candidate_user_id and candidate_wallet_address required"}), 400

    try:
        cand_uid = ObjectId(cand_uid_str)
    except Exception:
        return jsonify({"error": "Bad candidate_user_id"}), 400

    t = tasks.find_one({"_id": _id})
    if not t:
        return jsonify({"error": "Task not found"}), 404
    if str(t.get("created_by")) != str(uid):
        return jsonify({"error": "Only the creator can assign this task"}), 403
    if t.get("status") not in ("open", "reviewing", "changes_requested"):
        return jsonify({"error": f"Task is not assignable in status '{t.get('status')}'"}), 400

    creator_wallet_addr = (t.get("created_wallet") or "").strip()
    if not creator_wallet_addr:
        return jsonify({"error": "Task is missing creator_wallet_address"}), 400

    creator_w = wallets.find_one({"user_id": ObjectId(uid), "address": creator_wallet_addr})
    if not creator_w:
        return jsonify({"error": "Creator wallet not found"}), 404

    cand_w = wallets.find_one({"user_id": cand_uid, "address": cand_wallet_addr})
    if not cand_w:
        return jsonify({"error": "Candidate wallet not found"}), 404

    currency = (t.get("currency") or "RLUSD").upper()
    price = float(t.get("price") or 0)
    if price <= 0:
        return jsonify({"error": "Task price must be > 0"}), 400

    task_updates = {
        "assigned_to": cand_uid,
        "assigned_wallet": cand_w["address"],
        "assigned_at": now_utc(),
        "status": "assigned",
        "updated_at": now_utc(),
    }

    explorer_url = None
    escrow_seq = None
    create_hash = None

    if currency == "XRP":
        try:
            sender_wallet = Wallet.from_seed(creator_w["seed"])
        except Exception as e:
            return jsonify({"error": f"Bad creator seed: {e}"}), 500

        try:
            esc_res = create_escrow(
                sender_wallet=sender_wallet,
                dest_address=cand_w["address"],
                amount=str(price),
                currency="XRP",
                finish_after_seconds=7*24*3600,
            )
        except Exception as e:
            return jsonify({"error": f"Escrow create failed: {e}"}), 500

        res = getattr(esc_res, "result", {}) or {}
        engine_result = (res.get("engine_result") or "").upper()
        txj = res.get("tx_json") or {}
        meta = res.get("meta") or {}
        tx_result = (meta.get("TransactionResult") or engine_result).upper()

        if not tx_result.startswith("TES"):
            return jsonify({
                "error": "Escrow create not successful",
                "engine_result": engine_result,
                "tx_result": tx_result,
                "message": res.get("engine_result_message"),
            }), 500

        create_hash = (
            txj.get("hash")
            or res.get("hash")
            or res.get("tx_hash")
            or (res.get("transaction") or {}).get("hash")
        )

        escrow_seq = (
            txj.get("Sequence")
            or (res.get("transaction") or {}).get("Sequence")
            or res.get("Sequence")
        )

        if (not escrow_seq) and create_hash:
            try:
                tx_lookup = CLIENT.request(Tx(transaction=create_hash))
                txdoc = (tx_lookup.result or {}).get("tx") or {}
                escrow_seq = txdoc.get("Sequence")
            except Exception:
                pass

        if not escrow_seq:
            return jsonify({
                "error": "Escrow create succeeded but no Sequence found",
                "debug": {"have_tx_json": bool(txj), "have_hash": bool(create_hash), "top_keys": list(res.keys())}
            }), 500

        escrows.insert_one({
            "type": "xrp_escrow",
            "task_id": _id,
            "creator_id": ObjectId(uid),
            "solver_id": cand_uid,
            "from_address": creator_w["address"],
            "to_address": cand_w["address"],
            "amount_xrp": price,
            "escrow_sequence": int(escrow_seq),
            "create_tx_hash": create_hash,
            "status": "escrow_open",
            "created_at": now_utc(),
        })

        task_updates.update({
            "escrow_sequence": int(escrow_seq),
            "hold_status": "escrow_open",
            "hold_tx_hash": create_hash,
        })

        if create_hash:
            explorer_url = f"https://testnet.xrpl.org/transactions/{create_hash}"

    else:
        task_updates.update({"hold_status": "iou_hold", "hold_tx_hash": None})

    tasks.update_one({"_id": _id}, {"$set": task_updates})

    out = {
        "ok": True,
        "task_id": str(_id),
        "assigned_to": str(cand_uid),
        "assigned_wallet": cand_w["address"],
        "currency": currency,
        "price": price,
        "status": task_updates["status"],
    }
    if escrow_seq is not None:
        out["escrow_sequence"] = int(escrow_seq)
    if create_hash:
        out["create_tx_hash"] = create_hash
        out["explorer_url"] = explorer_url

    return jsonify(out)

@app.route("/tasks/<task_id>/submit", methods=["POST", "OPTIONS"])
@jwt_required()
def submit_solution(task_id):
    if request.method == "OPTIONS": return ("", 200)
    uid = get_jwt_identity()
    data = request.json or {}
    answer = (data.get("answer") or "").strip()
    if not answer: return jsonify({"error":"answer required"}), 400
    try: _id = ObjectId(task_id)
    except Exception: return jsonify({"error":"Bad task id"}), 400
    t = tasks.find_one({"_id": _id})
    if not t: return jsonify({"error":"Task not found"}), 404
    if str(t.get("assigned_to")) != uid:
        return jsonify({"error":"Only assigned solver can submit"}), 403
    if t.get("status") not in ["assigned","changes_requested"]:
        return jsonify({"error":"Task not ready for submission"}), 400

    subs = t.get("submissions", [])
    version = 1 + (subs[-1]["version"] if subs else 0)
    subs.append({
        "version": version,
        "answer": answer,
        "wallet": t.get("assigned_wallet"),
        "solver_id": ObjectId(uid),
        "submitted_at": now_utc()
    })
    tasks.update_one({"_id": _id}, {"$set": {"submissions": subs, "status": "under_review", "updated_at": now_utc()}})
    return jsonify({"ok": True, "version": version})

@app.route("/tasks/<task_id>/request_changes", methods=["POST", "OPTIONS"])
@jwt_required()
def request_changes(task_id):
    if request.method == "OPTIONS": return ("", 200)
    uid = get_jwt_identity()
    data = request.json or {}
    comments = (data.get("comments") or "").strip()
    if not comments: return jsonify({"error":"comments required"}), 400
    try: _id = ObjectId(task_id)
    except Exception: return jsonify({"error":"Bad task id"}), 400
    t = tasks.find_one({"_id": _id})
    if not t: return jsonify({"error":"Task not found"}), 404
    if not t.get("created_by") or str(t["created_by"]) != uid:
        return jsonify({"error":"Only creator can request changes"}), 403
    if t.get("status") != "under_review":
        return jsonify({"error":"Task not under review"}), 400
    if not t.get("submissions"):
        return jsonify({"error":"No submission to review"}), 400

    last_ver = t["submissions"][-1]["version"]
    revs = t.get("reviews", [])
    revs.append({
        "version": last_ver,
        "comments": comments,
        "reviewer_id": ObjectId(uid),
        "created_at": now_utc(),
        "type": "changes_requested"
    })
    tasks.update_one({"_id": _id}, {"$set": {"reviews": revs, "status": "changes_requested", "updated_at": now_utc()}})
    return jsonify({"ok": True})

@app.route("/tasks/<task_id>/approve", methods=["POST", "OPTIONS"])
@jwt_required()
def approve_task(task_id):
    if request.method == "OPTIONS": return ("", 200)
    uid = get_jwt_identity()
    try: _id = ObjectId(task_id)
    except Exception: return jsonify({"error":"Bad task id"}), 400
    t = tasks.find_one({"_id": _id})
    if not t: return jsonify({"error":"Task not found"}), 404
    if not t.get("created_by") or str(t["created_by"]) != uid:
        return jsonify({"error":"Only creator can approve"}), 403
    if t.get("status") != "under_review":
        return jsonify({"error":"Task must be under review to approve"}), 400

    amount = float(t["price"])
    currency = t.get("currency","RLUSD")
    paid_hash = None

    if currency == "RLUSD":
        dest = t.get("assigned_wallet")
        if not dest: return jsonify({"error":"No solver wallet recorded"}), 400
        try:
            tx = rl_usd_payment(ESCROW_HOT_SEED, dest, amount)
            paid_hash = tx.result.get("hash")
            escrows.update_one(
                {"task_id": _id, "type":"rlusd_hold", "status":"held"},
                {"$set": {"status":"released", "release_tx_hash": paid_hash, "released_at": now_utc()}}
            )
        except Exception as e:
            return jsonify({"error": f"Payout failed: {str(e)}"}), 500
    else:
        seq = t.get("escrow_sequence")
        if not seq:
            return jsonify({"error":"No escrow sequence on task"}), 400
        solver_w = wallets.find_one({"address": t.get("assigned_wallet"), "user_id": t.get("assigned_to")})
        if not solver_w:
            return jsonify({"error":"Solver wallet not found"}), 400
        creator_addr = t.get("created_wallet")
        try:
            fin_res = finish_escrow(Wallet.from_seed(solver_w["seed"]), owner=creator_addr, escrow_sequence=int(seq))
            paid_hash = fin_res.result.get("hash")
            escrows.update_one(
                {"task_id": _id, "type":"xrp_escrow", "escrow_sequence": int(seq)},
                {"$set": {"status":"finished", "finish_tx_hash": paid_hash, "finished_at": now_utc()}}
            )
        except Exception as e:
            return jsonify({"error": f"Escrow finish failed: {str(e)}"}), 500

    tasks.update_one(
        {"_id": _id},
        {"$set": {
            "status": "paid",
            "paid_tx_hash": paid_hash,
            "paid_at": now_utc(),
            "updated_at": now_utc(),
            "hold_status": "released" if currency=="RLUSD" else "escrow_finished"
        }}
    )
    return jsonify({"ok": True, "tx_hash": paid_hash})

# ---------------- AI REVIEW (Gemini if available, fallback heuristics) ----------------
def _heuristic_ai_review(answer: str, min_chars: int = 400):
    text = (answer or "").strip()
    if len(text) < min_chars:
        need = f"at least {min_chars} characters"
        return {"pass": False, "reason": f"Too short — please expand to {need} with original content and concrete details."}
    words = [w.lower() for w in re.findall(r"[a-zA-Z0-9]+", text)]
    total = len(words)
    uniq = len(set(words))
    if total > 0 and (uniq / total) < 0.35:
        return {"pass": False, "reason": "Text appears highly repetitive / templated. Please rewrite in your own words with more specifics."}
    bigrams = list(zip(words, words[1:]))
    if bigrams:
        from collections import Counter
        top = Counter(bigrams).most_common(1)[0][1]
        if top / max(1, len(bigrams)) > 0.15:
            return {"pass": False, "reason": "Detected repeated phrases. Please reduce repetition and add original explanation or examples."}
    return {"pass": True, "reason": "Meets basic quality checks."}

def ai_review_submission(task_doc, submission_text):
    api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    try:
        import google.generativeai as genai
        if api_key:
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel("gemini-1.5-flash")
            prompt = (
                "You are reviewing a submission for quality and originality.\n"
                f"Task topic: {task_doc.get('topic') or 'General'}\n"
                "Instructions:\n"
                "1) Check if the text is likely copy-paste (generic boilerplate, over-quoted, low originality).\n"
                "2) Check for length & substance; require clear, specific details/examples.\n"
                "3) Reply ONLY in JSON: {\"pass\": true|false, \"reason\": \"short explanation\"}.\n\n"
                "Submission:\n"
                f"{submission_text}"
            )
            resp = model.generate_content(prompt)
            text = (resp.text or "").strip()
            start = min([i for i in [text.find("{"), text.find("[")] if i != -1] or [-1])
            if start != -1:
                import json
                j = json.loads(text[start:])
                ok = bool(j.get("pass"))
                reason = str(j.get("reason") or ("Looks good." if ok else "Needs revision."))
                return {"pass": ok, "reason": reason}
    except Exception:
        pass
    return _heuristic_ai_review(submission_text)

@app.route("/tasks/<task_id>/ai/review_latest", methods=["POST", "OPTIONS"])
@jwt_required()
def ai_review_latest(task_id):
    if request.method == "OPTIONS": return ("", 200)
    uid = get_jwt_identity()
    try: _id = ObjectId(task_id)
    except Exception: return jsonify({"error": "Bad task id"}), 400
    t = tasks.find_one({"_id": _id})
    if not t: return jsonify({"error": "Task not found"}), 404
    if str(t.get("created_by")) != str(uid):
        return jsonify({"error": "Only the creator can run AI review"}), 403
    if not t.get("ai_review_enabled"):
        return jsonify({"error": "AI review not enabled for this task"}), 400
    subs = t.get("submissions") or []
    if not subs: return jsonify({"error": "No submission to review"}), 400

    last = subs[-1]
    answer = (last.get("answer") or "").strip()
    if not answer: return jsonify({"error": "Submission is empty"}), 400

    verdict = ai_review_submission(t, answer)
    ok = bool(verdict.get("pass"))
    reason = str(verdict.get("reason") or "")

    if ok:
        tasks.update_one(
            {"_id": _id},
            {"$set": {"ai_last_verdict": "pass", "ai_last_reason": reason, "ai_passed_at": now_utc(), "updated_at": now_utc()}}
        )
        return jsonify({"ok": True, "verdict": "pass", "reason": reason})

    revs = t.get("reviews", [])
    last_ver = last.get("version", 1)
    revs.append({
        "version": last_ver,
        "comments": f"[AI Review] {reason}",
        "reviewer_id": ObjectId(uid),
        "created_at": now_utc(),
        "type": "changes_requested"
    })
    tasks.update_one(
        {"_id": _id},
        {"$set": {
            "reviews": revs,
            "status": "changes_requested",
            "ai_last_verdict": "fail",
            "ai_last_reason": reason,
            "updated_at": now_utc(),
        }}
    )
    return jsonify({"ok": True, "verdict": "fail", "reason": reason})

# ---------------- AI candidate ranking (simple, keeps UI happy) ----------------
@app.route("/tasks/<task_id>/ai/rank_candidates", methods=["POST", "OPTIONS"])
@jwt_required()
def ai_rank_candidates(task_id):
    if request.method == "OPTIONS": return ("", 200)
    uid = get_jwt_identity()
    try: _id = ObjectId(task_id)
    except Exception: return jsonify({"error":"Bad task id"}), 400
    t = tasks.find_one({"_id": _id})
    if not t: return jsonify({"error":"Task not found"}), 404
    if str(t.get("created_by")) != str(uid):
        return jsonify({"error":"Only the creator can rank"}), 403

    cands = t.get("candidates") or []
    uid_list = [str(c.get("user_id")) for c in cands if c.get("user_id")]
    stats_map = get_solver_stats_for_user_ids(uid_list)

    rankings = []
    for c in cands:
        cu = users.find_one({"_id": c["user_id"]}, {"expertise":1, "email":1})
        exp = [normalize_topic(x) for x in (cu.get("expertise") or [])]
        stats = stats_map.get(str(c["user_id"]), {})
        solved_total = int(stats.get("total", 0))
        by_topic = stats.get("by_topic", {})
        topic = normalize_topic(t.get("topic") or "General")
        good_topic = 1 if (topic in exp or by_topic.get(topic, 0) > 0) else 0
        score = good_topic * 5 + min(solved_total, 5)
        reason_parts = []
        reason_parts.append(f"{solved_total} tasks solved")
        if good_topic: reason_parts.append(f"matching expertise in {topic}")
        else: reason_parts.append(f"no history in {topic}")
        rankings.append({
            "user_id": str(c["user_id"]),
            "score": int(score),
            "reason": ", ".join(reason_parts)
        })

    rankings.sort(key=lambda x: (-x["score"], x["user_id"]))
    return jsonify({"ok": True, "model": "fallback", "rankings": rankings})

# ---------------- DEV ----------------
@app.route("/dev")
def dev_dashboard():
    wallets_info = [
        {"address": w["address"], "secret": "hidden", "balance": get_xrp_balance(w["address"])}
        for w in wallets.find({})
    ]
    escrows_info = list(escrows.find({}))
    html = """
    <html><body>
      <h1>Developer Dashboard</h1>
      <h2>Wallets ({{ wallets|length }})</h2>
      <table border="1" cellspacing="0" cellpadding="4">
      <tr><th>Address</th><th>Secret</th><th>Balance (XRP)</th></tr>
      {% for w in wallets %}<tr><td>{{ w.address }}</td><td>{{ w.secret }}</td><td>{{ w.balance }}</td></tr>{% endfor %}
      </table>
      <h2>Escrows ({{ escrows|length }})</h2>
      <table border="1" cellspacing="0" cellpadding="4">
        <tr><th>Type</th><th>Task</th><th>From</th><th>To</th><th>Amount</th><th>Sequence</th><th>Status</th><th>Create TX</th><th>Finish/Release TX</th></tr>
        {% for e in escrows %}
        <tr>
          <td>{{ e.type }}</td>
          <td>{{ e.task_id }}</td>
          <td>{{ e.from_address }}</td>
          <td>{{ e.to_address if e.to_address else "-" }}</td>
          <td>{{ e.amount_rlusd if e.type == 'rlusd_hold' else e.amount_xrp }}</td>
          <td>{{ e.escrow_sequence if e.escrow_sequence else "-" }}</td>
          <td>{{ e.status }}</td>
          <td>{{ e.create_tx_hash if e.create_tx_hash else e.hold_tx_hash if e.hold_tx_hash else "-" }}</td>
          <td>{{ e.finish_tx_hash if e.finish_tx_hash else e.release_tx_hash if e.release_tx_hash else "-" }}</td>
        </tr>
        {% endfor %}
      </table>
    </body></html>
    """
    return render_template_string(html, wallets=wallets_info, escrows=escrows_info)

if __name__ == "__main__":
    app.run(debug=False, use_reloader=False)