import React, { useEffect, useMemo, useState } from "react";

const FALLBACK_TOPICS = [
  "Cryptography", "Zero-Knowledge", "Smart Contracts", "XRPL",
  "DeFi", "NFTs", "Consensus", "Security Audit",
  "Wallet Development", "APIs & SDKs",
  "Front-end (React)", "Back-end (Flask)",
  "Performance", "Gas Optimization",
  "Rust", "Go", "TypeScript", "Python",
  "Data Structures", "Algorithms", "Mathematics",
  "UX/UI", "DevOps", "Testing/QA"
];

const css = `
  :root { --bg:#0b0d10; --card:#11151a; --muted:#9aa4af; --text:#e5ecf3; --accent:#78c6ff; --ok:#22c55e; --err:#ef4444; }
  *{box-sizing:border-box}
  html, body, #root { min-height: 100%; width: 100%; }
  html, body { background: var(--bg); }
  #root { background: inherit; }
  body{margin:0;font:14px/1.4 system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, "Helvetica Neue", Arial; color:var(--text); background:var(--bg);} 
  header{padding:14px 16px;border-bottom:1px solid #1f2937;display:flex;gap:12px;align-items:center}
  .brand{display:flex;flex-direction:column;gap:2px}
  .brand h1{font-size:16px;letter-spacing:.3px;margin:0}
  .tagline{font-size:12px;color:var(--muted)}
  .header-actions{margin-left:auto;display:flex;gap:8px;flex-wrap:wrap;align-items:center}
  button{padding:8px 10px;border-radius:10px;border:1px solid #2a3441;background:#0e141a;color:var(--text);cursor:pointer}
  button:hover{border-color:#344355}
  input,select,textarea{width:100%;padding:8px 10px;border-radius:8px;border:1px solid #2a3441;background:#0e1217;color:var(--text)}
  label{display:block;margin:8px 0 4px;color:var(--muted)}
  .muted{color:var(--muted)}
  .ok{color:var(--ok)} .err{color:var(--err)}
  .mono{font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace}

  .main { min-height: calc(100vh - 66px); display: flex; flex-direction: column; width: 100%; }
  .center-wrap { flex: 1; display: flex; align-items: stretch; justify-content: stretch; }
  .center-col { width: 100%; display: grid; gap: 16px; padding: 24px; max-width: 1100px; margin: 0 auto; }

  .card{background:var(--card);border:1px solid #1f2937;border-radius:12px;padding:14px;width:100%}
  .wallet-row { border:1px solid #2a3441; border-radius:10px; padding:10px; display:flex; gap:8px; align-items:baseline; justify-content:space-between; }
  .tasks-grid { display:grid; gap:8px; }
  .task-item { border:1px solid #2a3441; border-radius:10px; padding:12px; cursor:pointer; }
  .task-item:hover { border-color:#344355; }

  .tabs { display:flex; gap:8px; margin-bottom:8px; }
  .tab { padding:6px 10px; border-radius:8px; border:1px solid #2a3441; cursor:pointer; }
  .tab.active { border-color: var(--accent); box-shadow: 0 0 0 1px rgba(120,198,255,0.2) inset; }

  .chips { display:flex; flex-wrap:wrap; gap:8px; }
  .chip { border:1px solid #2a3441; border-radius:999px; padding:6px 10px; cursor:pointer; }
  .chip.on { border-color: var(--accent); box-shadow: 0 0 0 1px rgba(120,198,255,0.2) inset; }

  .toast-wrap { position: fixed; right: 16px; bottom: 16px; display: grid; gap: 8px; z-index: 9999; }
  .toast { border-radius: 10px; padding: 10px 12px; display:flex; gap:8px; align-items:center; }
  .toast.success { background: #10331b; border:1px solid #1c5a30; }
  .toast.error { background: #3a1214; border:1px solid #7a2e32; }
  .badge{ border:1px solid #2a3441; border-radius:999px; padding:2px 8px; font-size:12px; }
  .mini { border:1px solid #2a3441; border-radius:8px; padding:8px; }

  /* auth card smaller & centered */
  .auth-wrap{display:flex;align-items:center;justify-content:center;padding:32px}
  .auth-card{max-width:360px;margin:0 auto}
`;

function useToasts() {
  const [toasts, setToasts] = useState([]);
  const notify = (type, text) => {
    const id = Math.random().toString(36).slice(2);
    setToasts(t => [...t, { id, type, text }]);
    setTimeout(() => setToasts(t => t.filter(x => x.id !== id)), 2600);
  };
  const UI = (
    <div className="toast-wrap">
      {toasts.map(t => (
        <div key={t.id} className={`toast ${t.type}`}>
          <div className="mono">{t.type === "success" ? "✓" : "✕"}</div>
          <div>{t.text}</div>
        </div>
      ))}
    </div>
  );
  return { notify, UI };
}
function useConfirm() {
  const [state, setState] = useState({ open: false, title: "", message: "", okText: "OK", cancelText: "Cancel", resolve: null });
  const confirm = ({ title = "Confirm", message = "Are you sure?", okText = "OK", cancelText = "Cancel" } = {}) =>
    new Promise((resolve) => setState({ open: true, title, message, okText, cancelText, resolve }));
  const onClose = (val) => { const r = state.resolve; setState(s => ({ ...s, open: false, resolve: null })); r?.(val); };
  const ConfirmUI = () => !state.open ? null : (
    <div className="modal-backdrop" onClick={() => onClose(false)}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h3>{state.title}</h3><p>{state.message}</p>
        <div className="row">
          <button className="btn" onClick={() => onClose(false)}>{state.cancelText}</button>
          <button className="btn danger" onClick={() => onClose(true)}>{state.okText}</button>
        </div>
      </div>
    </div>
  );
  return { confirm, ConfirmUI };
}

export default function App() {
  const { notify, UI: Toasts } = useToasts();
  const { confirm, ConfirmUI } = useConfirm();

  const [base, setBase] = useState("http://127.0.0.1:5000");
  const cleanBase = () => base.replace(/\/$/, "");
  const [pingStatus, setPingStatus] = useState("");
  const [aiBusy, setAiBusy] = useState(false);
  const [aiRankings, setAiRankings] = useState(null);

  // auth
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [token, setToken] = useState(localStorage.getItem("jwt") || "");
  const [me, setMe] = useState(null);
  const [phone, setPhone] = useState("");

  // nav
  const [showAccount, setShowAccount] = useState(false);
  const [showCreateTask, setShowCreateTask] = useState(false);
  const [showTasks, setShowTasks] = useState(true);

  // topics
  const [taskTopics, setTaskTopics] = useState([]); // global topics for task creation/filter
  const taskTopicsToUse = taskTopics.length ? taskTopics : FALLBACK_TOPICS;
  const [myTopics, setMyTopics] = useState([]);     // personal topics for expertise
  const [expertise, setExpertise] = useState([]);
  const [customTopicName, setCustomTopicName] = useState("");

  // wallets
  const [myWallets, setMyWallets] = useState([]);
  const [fundAmtByAddr, setFundAmtByAddr] = useState({});

  // tasks
  const [tasks, setTasks] = useState([]);
  const [taskFilter, setTaskFilter] = useState("all"); // all | created | assigned
  const [selectedTask, setSelectedTask] = useState(null);
  const [topicFilter, setTopicFilter] = useState("");
  const [showArchive, setShowArchive] = useState(false);
  const [archivedTasks, setArchivedTasks] = useState([]);

  // create task form
  const [taskTitle, setTaskTitle] = useState("");
  const [taskDesc, setTaskDesc] = useState("");
  const [taskPrice, setTaskPrice] = useState("1");
  const [taskFromAddr, setTaskFromAddr] = useState("");
  const [taskTopic, setTaskTopic] = useState(""); // IMPORTANT: define this or you'll get a blank screen
  const [holdMethod, setHoldMethod] = useState("RLUSD"); // RLUSD or XRP
  const [aiReviewOn, setAiReviewOn] = useState(true);    // toggle AI Review Assistant

  // apply/submit forms
  const [applyWallet, setApplyWallet] = useState("");
  const [applyNote, setApplyNote] = useState("");
  const [solveAnswer, setSolveAnswer] = useState("");
  const [reviewComments, setReviewComments] = useState("");

  // tx details
  const [holdTxDetails, setHoldTxDetails] = useState(null);
  const [paidTxDetails, setPaidTxDetails] = useState(null);

  const onPing = async () => {
    try {
      const r = await fetch(cleanBase() + "/");
      const t = await r.text();
      setPingStatus(r.ok ? "Server OK" : "Server error");
      console.log("Ping /", t);
    } catch {
      setPingStatus("No response");
    }
  };

  const refreshAccessToken = async () => {
    const rt = localStorage.getItem("jwt_refresh");
    if (!rt) throw new Error("no refresh token");
    const res = await fetch(cleanBase() + "/auth/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${rt}` },
    });
    const data = await res.json();
    if (!res.ok || !data.access_token) throw new Error("refresh failed");
    setToken(data.access_token);
    localStorage.setItem("jwt", data.access_token);
    return data.access_token;
  };
  const fetchWithRetry = async (method, path, body) => {
    const make = async (access) => {
      const res = await fetch(cleanBase() + path, {
        method,
        headers: { "Content-Type": "application/json", ...(access ? { Authorization: `Bearer ${access}` } : {}) },
        body: body ? JSON.stringify(body) : undefined,
      });
      let json; try { json = await res.json(); } catch { json = { raw: true }; }
      return { res, json };
    };
    const access0 = localStorage.getItem("jwt") || token || "";
    let { res, json } = await make(access0);
    const expired = res.status === 401 && typeof json?.msg === "string" && json.msg.toLowerCase().includes("token has expired");
    if (!expired) {
      if (!res.ok) throw new Error(json?.error || json?.msg || "Request failed");
      return json;
    }
    await refreshAccessToken();
    const access1 = localStorage.getItem("jwt");
    ({ res, json } = await make(access1));
    if (!res.ok) throw new Error(json?.error || json?.msg || "Request failed");
    return json;
  };
  const post = (p, b) => fetchWithRetry("POST", p, b);
  const get = (p) => fetchWithRetry("GET", p);
  const del = (p, b) => fetchWithRetry("DELETE", p, b);

  const fetchTaskTopics = async () => {
    try {
      const r = await fetch(cleanBase() + "/topics");
      const j = await r.json();
      setTaskTopics(Array.isArray(j?.topics) ? j.topics : []);
    } catch {
      setTaskTopics([]);
    }
  };
  const fetchMyTopics = async () => {
    try {
      const j = await get("/me/topics");
      setMyTopics(Array.isArray(j?.topics) ? j.topics : []);
    } catch {
      setMyTopics([]);
    }
  };
  const fetchMe = async () => {
    const j = await get("/me");
    setMe(j.user || null);
    setPhone(j.user?.phone || "");
  };
  const fetchExpertise = async () => {
    try {
      const j = await get("/me/expertise");
      setExpertise(j.expertise || []);
    } catch {}
  };
  const loadMyWallets = async () => {
    try {
      const j = await get("/my/wallets");
      setMyWallets(Array.isArray(j.wallets) ? j.wallets : []);
    } catch {}
  };
  const loadTasks = async (topic = "", archived = false) => {
    const q = new URLSearchParams();
    if (topic) q.set("topic", topic);
    if (archived) q.set("archived", "1");
    try {
      const j = await get(`/tasks${q.toString() ? `?${q}` : ""}`);
      const arr = Array.isArray(j.tasks) ? j.tasks : [];
      archived ? setArchivedTasks(arr) : setTasks(arr);
    } catch {
      archived ? setArchivedTasks([]) : setTasks([]);
    }
  };
  const refreshAll = async () => {
    try {
      await Promise.allSettled([fetchTaskTopics(), fetchMe(), fetchExpertise(), fetchMyTopics(), loadMyWallets()]);
      await loadTasks(topicFilter, showArchive);
    } catch {}
  };

  const onAddWalletMy = async () => {
    try { await post("/my/add_wallet", {}); notify("success", "Wallet added"); await loadMyWallets(); }
    catch { notify("error", "Failed to add wallet"); }
  };
  const onFundWalletRLUSD = async (address) => {
    const raw = (fundAmtByAddr[address] || "").trim();
    if (!raw) { notify("error", "Enter RLUSD amount"); return; }
    try {
      await post("/send_rlusd", { destination: address, amount: String(raw) });
      notify("success", `Funded ${raw} RLUSD`);
      await loadMyWallets();
    } catch { notify("error", "Funding failed"); }
  };

  const onCreateTask = async () => {
    const title = taskTitle.trim() || "Untitled Task";
    const description = taskDesc.trim();
    const price = Number(taskPrice || 0);
    const from_address = taskFromAddr || "";
    const topic = (taskTopic || "").trim();
    const currency = holdMethod === "XRP" ? "XRP" : "RLUSD";
    if (!from_address) { notify("error", "Pick a wallet"); return; }
    if (!description || !(price > 0)) { notify("error", "Description and positive price required"); return; }
    if (!topic) { notify("error", "Pick a topic"); return; }
    try {
      const j = await post("/tasks", { title, description, price, from_address, topic, currency, ai_review_enabled: !!aiReviewOn });
      notify("success", "Task created");
      setTaskTitle(""); setTaskDesc(""); setTaskPrice("1");
      await loadTasks(topicFilter);
      await loadMyWallets();
      await fetchTaskTopics();
      setShowCreateTask(false);
      setShowTasks(true);
      setSelectedTask(j.task || null);
    } catch (e) { notify("error", e.message || "Create task failed"); }
  };

  const onOpenTask = async (t) => {
    try { const j = await get(`/tasks/${t._id}`); setSelectedTask(j.task); }
    catch { setSelectedTask(t); }
    setShowTasks(true); setShowCreateTask(false); setShowAccount(false);
  };

  const onApply = async () => {
    if (!selectedTask) return;
    if (!applyWallet) { notify("error", "Choose your wallet"); return; }
    try {
      await post(`/tasks/${selectedTask._id}/apply`, { wallet: applyWallet, note: applyNote });
      const j = await get(`/tasks/${selectedTask._id}`);
      setSelectedTask(j.task);
      notify("success", "Applied");
    } catch (e) { notify("error", e.message || "Apply failed"); }
  };

  const onAssign = async (candidate_user_id, candidate_wallet_address) => {
    if (!selectedTask) return;
    if (!candidate_wallet_address) { notify("error", "Candidate has no wallet on file"); return; }
    try {
      await post(`/tasks/${selectedTask._id}/assign`, { candidate_user_id, candidate_wallet_address });
      const j = await get(`/tasks/${selectedTask._id}`);
      setSelectedTask(j.task);
      await loadTasks(topicFilter);
      notify("success", "Assigned solver");
    } catch (e) { notify("error", e.message || "Assign failed"); }
  };

  const onSubmitSolution = async () => {
    if (!selectedTask) return;
    const answer = solveAnswer.trim();
    if (!answer) { notify("error", "Answer required"); return; }
    try {
      await post(`/tasks/${selectedTask._id}/submit`, { answer });
      const j = await get(`/tasks/${selectedTask._id}`);
      setSelectedTask(j.task);
      setSolveAnswer("");
      notify("success", "Submitted");
    } catch (e) { notify("error", e.message || "Submit failed"); }
  };

  const onRequestChanges = async () => {
    if (!selectedTask) return;
    const comments = reviewComments.trim();
    if (!comments) { notify("error", "Comments required"); return; }
    try {
      await post(`/tasks/${selectedTask._id}/request_changes`, { comments });
      const j = await get(`/tasks/${selectedTask._id}`);
      setSelectedTask(j.task);
      setReviewComments("");
      notify("success", "Requested changes");
    } catch (e) { notify("error", e.message || "Request failed"); }
  };

  const onApproveAndPay = async () => {
    if (!selectedTask) return;
    try {
      const r = await post(`/tasks/${selectedTask._id}/approve`, {});
      const d = await get(`/tasks/${selectedTask._id}`);
      setSelectedTask(d.task);
      await loadTasks(topicFilter);
      await loadMyWallets();
      notify("success", "Paid to solver");
      if (r?.tx_hash) {
        const url = `https://testnet.xrpl.org/transactions/${r.tx_hash}`;
        window.open(url, "_blank", "noopener,noreferrer");
      }
    } catch (e) { notify("error", e.message || "Payout failed"); }
  };

  const fetchTx = async (hash, setFn) => {
    try {
      const r = await fetch(`${cleanBase()}/tx/${hash}`);
      const j = await r.json();
      if (!r.ok) throw new Error(j?.error || "TX lookup failed");
      setFn(j);
    } catch (e) {
      notify("error", e.message || "TX lookup failed");
    }
  };

  const needsAttention = (t) => {
    if (!me) return false;
    const uid = me._id;
    if (t.status === "under_review" && t.created_by === uid) return true;
    if (t.status === "changes_requested" && t.assigned_to === uid) return true;
    return false;
  };

  const filteredTasks = useMemo(() => {
    if (!me) return [];
    let arr = tasks;
    if (taskFilter === "created") arr = arr.filter(t => t.created_by === me._id);
    if (taskFilter === "assigned") arr = arr.filter(t => t.assigned_to === me._id);
    arr = arr.filter(t => t.status !== "paid");
    arr = [...arr].sort((a, b) => {
      const aAtt = needsAttention(a) ? 1 : 0;
      const bAtt = needsAttention(b) ? 1 : 0;
      if (aAtt !== bAtt) return bAtt - aAtt;
      const ta = new Date(a.updated_at || a.created_at || 0).getTime();
      const tb = new Date(b.updated_at || b.created_at || 0).getTime();
      return tb - ta;
    });
    return arr;
  }, [tasks, me, taskFilter]);

  const mergedTimeline = (task) => {
    const A = (task.submissions || []).map(s => ({ type: "submission", ts: s.submitted_at, title: `Submission v${s.version}`, body: s.answer }));
    const B = (task.reviews || []).map(r => ({ type: "review", ts: r.created_at, title: `Changes for v${r.version}`, body: r.comments }));
    const all = [...A, ...B].filter(x => x.ts).sort((a, b) => new Date(a.ts) - new Date(b.ts));
    return all;
  };

  const onAIRank = async () => {
    if (!selectedTask) return;
    setAiBusy(true);
    setAiRankings(null);
    try {
      const r = await post(`/tasks/${selectedTask._id}/ai/rank_candidates`, {});
      setAiRankings(Array.isArray(r.rankings) ? r.rankings : []);
      notify("success", r.model === "fallback" ? "AI fallback ranking ready" : "AI ranking ready");
    } catch (e) {
      notify("error", e.message || "AI ranking failed");
    } finally {
      setAiBusy(false);
    }
  };

  const onAICheckLatest = async () => {
    if (!selectedTask) return;
    try {
      setAiBusy(true);
      const r = await post(`/tasks/${selectedTask._id}/ai/review_latest`, {});
      const j = await get(`/tasks/${selectedTask._id}`);
      setSelectedTask(j.task);
      if (r.verdict === "pass") notify("success", "AI: submission passed");
      else notify("error", "AI: requested changes");
    } catch (e) {
      notify("error", e.message || "AI check failed");
    } finally {
      setAiBusy(false);
    }
  };

  useEffect(() => { (async () => { await fetchTaskTopics(); })(); }, []);
  useEffect(() => {
    if (token) {
      Promise.allSettled([fetchMe(), fetchExpertise(), fetchMyTopics()])
        .then(() => { loadMyWallets(); loadTasks(topicFilter); fetchTaskTopics(); });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token]);

  useEffect(() => {
    if (token) loadTasks(topicFilter, showArchive);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [topicFilter, showArchive]);

  useEffect(() => {
    if (showCreateTask && !taskTopic && taskTopicsToUse.length > 0) setTaskTopic(taskTopicsToUse[0]);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [showCreateTask, taskTopicsToUse]);

  const listToShow = showArchive ? archivedTasks : filteredTasks;

  // ------------- AUTH GATE -------------
  if (!token || !me) {
    return (
      <>
        <style>{css}</style>
        <header>
          <div className="brand">
            <h1>Help Me If You Can</h1>
          </div>
          <div className="header-actions">
            <small className="muted">{pingStatus}</small>
            <button onClick={onPing}>Ping</button>
          </div>
        </header>
        <div className="main auth-wrap">
          <div className="center-col">
            <div className="card auth-card">
              <h2>Sign in</h2>
              <label>Email</label>
              <input value={email} onChange={e => setEmail(e.target.value)} placeholder="you@example.com" />
              <label>Password</label>
              <input type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="••••••••" />
              <div style={{ display: 'flex', gap: 8, marginTop: 10 }}>
                <button onClick={async () => {
                  try {
                    const j = await post("/auth/login", { email, password });
                    setToken(j.access_token);
                    localStorage.setItem("jwt", j.access_token);
                    if (j.refresh_token) localStorage.setItem("jwt_refresh", j.refresh_token);
                    notify("success", "Logged in");
                  } catch (e) { notify("error", e.message || "Login failed"); }
                }}>Login</button>
                <button onClick={async () => {
                  try {
                    const j = await post("/auth/register", { email, password });
                    setToken(j.access_token);
                    localStorage.setItem("jwt", j.access_token);
                    if (j.refresh_token) localStorage.setItem("jwt_refresh", j.refresh_token);
                    notify("success", "Registered");
                  } catch (e) { notify("error", e.message || "Register failed"); }
                }}>Register</button>
              </div>
              <div style={{ marginTop: 12 }}>
                <small className="muted">Global topics loaded: {taskTopicsToUse.length}</small>
              </div>
            </div>
          </div>
        </div>
        {Toasts}
      </>
    );
  }

  // ------------- AUTHED UI -------------
  return (
    <>
      <style>{css}</style>
      <header>
        <div className="brand">
          <h1>Help Me If You Can</h1>
        </div>
        <div className="header-actions">
          <small>Signed in as <b>{me?.email}</b></small>
          <button
            onClick={async () => {
              if (showAccount) {
                setShowAccount(false);
                setShowCreateTask(false);
                setSelectedTask(null);
                setShowTasks(true);
                await loadTasks(topicFilter, showArchive);
              } else {
                setShowAccount(true);
                setShowCreateTask(false);
                setShowTasks(false);
                setSelectedTask(null);
              }
            }}
          >
            {showAccount ? "Hide My Account" : "My Account"}
          </button>
          <button
            onClick={() => {
              setShowCreateTask(true);
              setShowTasks(false);
              setShowAccount(false);
              setSelectedTask(null);
            }}
          >
            Create Task
          </button>
          <button
            onClick={async () => {
              setShowTasks(true);
              setShowCreateTask(false);
              setShowAccount(false);
              setSelectedTask(null);
              await refreshAll();
            }}
          >
            View Tasks
          </button>
          <button onClick={() => { setToken(""); localStorage.removeItem("jwt"); localStorage.removeItem("jwt_refresh"); setMe(null); setMyWallets([]); setShowAccount(false); setShowCreateTask(false); setShowTasks(true); setSelectedTask(null); notify("success", "Logged out"); }}>
            Logout
          </button>
        </div>
      </header>

      <div className="main">
        {/* My Account */}
        {showAccount && (
          <div className="center-wrap">
            <div className="center-col">
              <div className="card">
                <h2>My Account</h2>
                <small className="muted">Add personal topics, then select 3–5 as your expertise.</small>

                <label style={{marginTop:12}}>Add a personal topic</label>
                <div style={{display:'flex', gap:8}}>
                  <input placeholder="e.g. zkSNARK MSM" value={customTopicName} onChange={e=>setCustomTopicName(e.target.value)} />
                  <button onClick={async()=>{
                    const name = (customTopicName||"").trim();
                    if(!name){ notify("error","Enter a topic name"); return; }
                    try{
                      const r = await post("/me/topics",{name});
                      setMyTopics(r.topics || myTopics);
                      setCustomTopicName("");
                      notify("success","Added to your topics");
                    }catch(e){ notify("error", e.message || "Add topic failed"); }
                  }}>Add</button>
                  <button onClick={fetchMyTopics}>Reload my topics</button>
                </div>

                <label style={{marginTop:12}}>My Expertise (pick 3–5)</label>
                <div className="chips">
                  {(myTopics.length ? myTopics : []).map(t => {
                    const on = expertise.includes(t);
                    const blocked = !on && expertise.length >= 5;
                    return (
                      <div
                        key={t}
                        className={`chip ${on ? "on" : ""}`}
                        onClick={()=>{ if (!on && blocked) return; setExpertise(prev => on ? prev.filter(x=>x!==t) : [...prev,t]); }}
                        title={blocked ? "Max 5 topics" : ""}
                      >
                        {t}
                      </div>
                    );
                  })}
                  {myTopics.length === 0 && (
                    <small className="muted">No personal topics yet. Add a few above.</small>
                  )}
                </div>
                <div style={{display:'flex', gap:8, marginTop:8}}>
                  <button onClick={async()=>{
                    if (expertise.length < 3 || expertise.length > 5) { notify("error","Choose 3–5"); return; }
                    try { const r = await post("/me/expertise",{expertise}); setExpertise(r.expertise||expertise); notify("success","Expertise saved"); }
                    catch(e){ notify("error", e.message || "Save failed"); }
                  }}>Save Expertise</button>
                </div>

                <label style={{ marginTop: 12 }}>Mobile phone (optional)</label>
                <input placeholder="+1 555 123 4567" value={phone} onChange={e => setPhone(e.target.value)} />
                <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
                  <button onClick={async () => {
                    try {
                      const r = await post("/me/profile", { phone });
                      if (r?.user) setMe(r.user);
                      notify("success", "Profile updated");
                    } catch (e) { notify("error", e.message || "Save failed"); }
                  }}>Save Profile</button>
                </div>

                {/* Wallets */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', gap: 8, marginTop: 16 }}>
                  <div>
                    <small className="muted">Signed in as</small>
                    <div style={{ fontWeight: 600 }}>{me?.email}</div>
                  </div>
                  <div>
                    <button onClick={onAddWalletMy}>Add Wallet (auto RLUSD trustline)</button>
                    <button onClick={loadMyWallets} style={{ marginLeft: 8 }}>Refresh</button>
                  </div>
                </div>

                <label style={{ marginTop: 10 }}>Your Wallets</label>
                <div style={{ display: 'grid', gap: 8 }}>
                  {myWallets.map(w => (
                    <div key={w.address} className="wallet-row">
                      <div style={{ flex: 3 }}>
                        <div className="mono" style={{ overflowWrap: 'anywhere' }}>{w.address}</div>
                        <small className="muted">
                          XRP: <b>{w.xrp_balance ?? "?"}</b> · RLUSD: <b>{w.rlusd_balance ?? "?"}</b> · Held: <b>{w.held_rlusd ?? 0}</b> ·{" "}
                          Trustline RLUSD: <span className={w.trustline_rlusd ? "ok" : "err"}>{w.trustline_rlusd ? "✓" : "✗"}</span>
                        </small>
                      </div>
                      <div style={{ flex: 2, display:'flex', gap:8, alignItems:'center', justifyContent:'flex-end', flexWrap:'wrap' }}>
                        <input
                          style={{ maxWidth: 200 }}
                          placeholder="Amount (RLUSD)"
                          value={fundAmtByAddr[w.address] || ""}
                          onChange={e => setFundAmtByAddr(prev => ({ ...prev, [w.address]: e.target.value }))}
                        />
                        <button disabled={!w.trustline_rlusd} onClick={() => onFundWalletRLUSD(w.address)}>Fund (RLUSD)</button>
                        <button
                          onClick={async () => {
                            if (w.held_rlusd > 0) { notify("error", `Cannot delete. ${w.held_rlusd} RLUSD is held.`); return; }
                            const ok = window.confirm("Delete this wallet?");
                            if (!ok) return;
                            try {
                              await post("/my/delete_wallet", { address: w.address });
                              notify("success","Wallet deleted");
                              await loadMyWallets();
                            } catch { notify("error","Failed to delete wallet"); }
                          }}
                        >Delete</button>
                      </div>
                    </div>
                  ))}
                  {myWallets.length === 0 && <small className="muted">No wallets yet. Click “Add Wallet”.</small>}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Create Task */}
        {showCreateTask && (
          <div className="center-wrap">
            <div className="center-col">
              <div className="card">
                <h2>Create Task</h2>

                <label>Payment / Hold Method</label>
                <div style={{ display: 'flex', gap: 8 }}>
                  <select value={holdMethod} onChange={e => setHoldMethod(e.target.value)}>
                    <option value="RLUSD">RLUSD Hold (custodial)</option>
                    <option value="XRP">XRP Escrow (native)</option>
                  </select>
                </div>

                <label style={{ marginTop: 8 }}>Fund from wallet</label>
                <select value={taskFromAddr} onChange={e => setTaskFromAddr(e.target.value)}>
                  <option value="" disabled>Choose a wallet…</option>
                  {myWallets.map(w => (
                    <option key={w.address} value={w.address}>
                      {w.address} — XRP {w.xrp_balance ?? "?"} · RLUSD {w.rlusd_balance ?? "?"} (Held {w.held_rlusd ?? 0})
                    </option>
                  ))}
                </select>

                <label style={{ marginTop: 8 }}>AI Review Assistant</label>
                <label style={{ display:'flex', alignItems:'center', gap:8 }}>
                  <input type="checkbox" checked={aiReviewOn} onChange={(e)=>setAiReviewOn(e.target.checked)} />
                  <span className="muted">Help catch low-effort / copy-paste submissions</span>
                </label>

                <label style={{marginTop:8, display:'flex', gap:8, alignItems:'center'}}>
                  <span>Topic</span>
                  <small className="muted">({taskTopicsToUse.length} available)</small>
                  <button onClick={fetchTaskTopics}>Reload</button>
                </label>
                <div style={{display:'grid', gridTemplateColumns:'1fr auto', gap:8}}>
                  <select value={taskTopic} onChange={e=>setTaskTopic(e.target.value)}>
                    <option value="" disabled>Choose a topic…</option>
                    {taskTopicsToUse.map(t => <option key={t} value={t}>{t}</option>)}
                  </select>
                  <button onClick={async()=>{
                    const name = prompt("Add a new global topic name (will be available to everyone):");
                    if(!name) return;
                    try{
                      const r = await post("/topics",{name});
                      setTaskTopics(r.topics || taskTopics);
                      setTaskTopic(name);
                      notify("success","Global topic added");
                    }catch(e){ notify("error", e.message || "Add topic failed"); }
                  }}>+ Add</button>
                </div>

                <label style={{ marginTop: 8 }}>Title (optional)</label>
                <input placeholder="Short task title" value={taskTitle} onChange={e => setTaskTitle(e.target.value)} />
                <label>Description</label>
                <textarea style={{ width: '100%', minHeight: 120 }} placeholder="Describe the task" value={taskDesc} onChange={e => setTaskDesc(e.target.value)} />
                <div style={{ display: 'flex', gap: 8, alignItems: 'flex-end' }}>
                  <div style={{ flex: 1 }}>
                    <label>Amount ({holdMethod === "XRP" ? "XRP" : "RLUSD"})</label>
                    <input type="number" step="0.000001" value={taskPrice} onChange={e => setTaskPrice(e.target.value)} />
                  </div>
                  <div style={{ flex: 'none' }}>
                    <button onClick={onCreateTask}>Create</button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* View Tasks (list) */}
        {showTasks && !selectedTask && (
          <div className="center-wrap">
            <div className="center-col">
              <div className="card">
                <h2>Tasks</h2>
                <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap', marginBottom: 8 }}>
                  <div className="tabs">
                    <div className={`tab ${taskFilter === 'all' ? 'active' : ''}`} onClick={() => setTaskFilter('all')}>All</div>
                    <div className={`tab ${taskFilter === 'created' ? 'active' : ''}`} onClick={() => setTaskFilter('created')}>Created by me</div>
                    <div className={`tab ${taskFilter === 'assigned' ? 'active' : ''}`} onClick={() => setTaskFilter('assigned')}>Assigned to me</div>
                    <div className={`tab ${showArchive ? 'active' : ''}`} onClick={() => setShowArchive(s => !s)} title="Toggle solved tasks">
                      {showArchive ? "Hide Archive" : "Show Archive"}
                    </div>
                  </div>
                  <div style={{ marginLeft: 'auto', minWidth: 240 }}>
                    <label style={{ margin: 0 }}>Filter by topic</label>
                    <select value={topicFilter} onChange={e => setTopicFilter(e.target.value)}>
                      <option value="">All topics</option>
                      {taskTopicsToUse.map(t => <option key={t} value={t}>{t}</option>)}
                    </select>
                  </div>
                </div>

                <div className="tasks-grid">
                  {listToShow.map(t => (
                    <div key={t._id} className="task-item" onClick={() => onOpenTask(t)}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', gap: 8 }}>
                        <div>
                          <div style={{ fontWeight: 600, display: 'flex', gap: 8, alignItems: 'center' }}>
                            {t.title || 'Untitled Task'}
                            {t.ai_last_verdict === 'pass' && <span className="badge ok">AI Verified</span>}
                            {needsAttention(t) && <span className="badge" style={{ borderColor: 'var(--accent)' }}>Needs review</span>}
                            {t.solved || t.status === 'paid' ? <span className="badge ok">Solved</span> : null}
                          </div>
                          <small className="muted">
                            Topic: {t.topic || '—'} · Status: {t.status} · Currency: {t.currency}
                            {t.created_by === me._id ? " · You created this" : ""}
                            {t.assigned_to === me._id ? " · Assigned to you" : ""}
                            {t.created_by_email ? ` · Creator: ${t.created_by_email}` : ""}
                          </small>
                        </div>
                        <div style={{ textAlign: 'right' }}>
                          <div style={{ fontWeight: 700, fontSize: 16 }}>Amount: {t.price} {t.currency}</div>
                        </div>
                      </div>
                      <div style={{ marginTop: 6 }} className="muted">{t.description}</div>
                    </div>
                  ))}
                  {listToShow.length === 0 && <small className="muted">{showArchive ? "No solved tasks." : "No tasks for this filter."}</small>}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Task detail */}
        {showTasks && selectedTask && (
          <div className="center-wrap">
            <div className="center-col">
              <div className="card">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <h2>{selectedTask.title || "Task"}</h2>
                  <div style={{ display: 'flex', gap: 8 }}>
                    {selectedTask.created_by === me._id && selectedTask.status === 'open' && !selectedTask.assigned_to && (
                      <button
                        onClick={async () => {
                          if (!window.confirm("Delete this task? RLUSD hold (if any) will be refunded.")) return;
                          try {
                            await del(`/tasks/${selectedTask._id}`);
                            notify("success", "Task deleted");
                            setSelectedTask(null);
                            await loadTasks(topicFilter, false);
                            await loadMyWallets();
                          } catch (e) { notify("error", e.message || "Delete failed"); }
                        }}
                      >Delete</button>
                    )}
                    <button onClick={() => { setHoldTxDetails(null); setPaidTxDetails(null); setSelectedTask(null); }}>
                      Back
                    </button>
                  </div>
                </div>

                <div className="muted" style={{ marginTop: 6 }}>{selectedTask.description}</div>
                <div style={{ marginTop: 8, display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
                  <div><b>Topic:</b> {selectedTask.topic || "—"}</div>
                  <div><b>Amount:</b> {selectedTask.price} {selectedTask.currency}</div>
                  <div><b>Status:</b> {selectedTask.status}</div>
                  <div><b>Creator:</b> {selectedTask.created_by_email || selectedTask.created_by}</div>
                  <div>
                    <b>Hold:</b> {selectedTask.hold?.status || "n/a"}
                    {selectedTask.hold?.tx_hash && (
                      <>
                        {" · "}
                        <button onClick={() => fetchTx(selectedTask.hold.tx_hash, setHoldTxDetails)}>View hold TX</button>
                        {" · "}
                        <a className="muted" href={`https://testnet.xrpl.org/transactions/${selectedTask.hold.tx_hash}`} target="_blank" rel="noreferrer">Open in explorer</a>
                      </>
                    )}
                    {selectedTask.hold?.escrow_sequence ? <> · Escrow seq: {selectedTask.hold.escrow_sequence}</> : null}
                  </div>
                  {selectedTask.paid_tx_hash && (
                    <div>
                      <b>Payout:</b>{" "}
                      <button onClick={() => fetchTx(selectedTask.paid_tx_hash, setPaidTxDetails)}>View payout TX</button>
                      {" · "}
                      <a className="muted" href={`https://testnet.xrpl.org/transactions/${selectedTask.paid_tx_hash}`} target="_blank" rel="noreferrer">Open in explorer</a>
                    </div>
                  )}
                </div>

                {(holdTxDetails || paidTxDetails) && (
                  <div className="mini" style={{ marginTop: 8 }}>
                    {holdTxDetails && (<pre className="mono" style={{ whiteSpace: 'pre-wrap' }}>{JSON.stringify(holdTxDetails, null, 2)}</pre>)}
                    {paidTxDetails && (<pre className="mono" style={{ whiteSpace: 'pre-wrap' }}>{JSON.stringify(paidTxDetails, null, 2)}</pre>)}
                  </div>
                )}

                {/* AI Review row (creator) */}
                {selectedTask.ai_review_enabled && selectedTask.created_by === me._id && (
                  <div className="mini" style={{ marginTop: 8, display:'flex', gap:12, alignItems:'center', flexWrap:'wrap' }}>
                    <div>
                      <b>AI Review:</b>{" "}
                      {selectedTask.ai_last_verdict === "pass" ? (
                        <span className="ok">Passed</span>
                      ) : selectedTask.ai_last_verdict === "fail" ? (
                        <span className="err">Needs rework</span>
                      ) : (
                        <span className="muted">Not run yet</span>
                      )}
                      {selectedTask.ai_last_reason && (
                        <span className="muted"> — {selectedTask.ai_last_reason}</span>
                      )}
                    </div>
                    <button
                      onClick={onAICheckLatest}
                      disabled={aiBusy || !(selectedTask.submissions||[]).length}
                      title={!(selectedTask.submissions||[]).length ? "No submission yet" : ""}
                    >
                      {aiBusy ? "Checking…" : "Run AI Check"}
                    </button>
                  </div>
                )}

                {/* OPEN: apply (not creator) */}
                {selectedTask.status === 'open' && selectedTask.created_by !== me._id && (
                  <div style={{ marginTop: 12 }}>
                    <label>Choose wallet to receive payment</label>
                    <select value={applyWallet} onChange={e => setApplyWallet(e.target.value)}>
                      <option value="" disabled>Choose wallet…</option>
                      {myWallets.map(w => (
                        <option key={w.address} value={w.address}>
                          {w.address} — RLUSD {w.rlusd_balance ?? "?"} · XRP {w.xrp_balance ?? "?"}
                        </option>
                      ))}
                    </select>
                    <label style={{ marginTop: 8 }}>Note (optional)</label>
                    <input value={applyNote} onChange={e => setApplyNote(e.target.value)} placeholder="Why you're a good fit…" />
                    <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
                      <button onClick={onApply}>Apply</button>
                    </div>
                    {Array.isArray(selectedTask.candidates) && selectedTask.candidates.some(c => c.user_id === me._id) && (
                      <small className="muted" style={{ display: 'block', marginTop: 6 }}>You have applied.</small>
                    )}
                  </div>
                )}

                {/* OPEN: creator sees candidates with STATS */}
                {selectedTask.status === 'open' && selectedTask.created_by === me._id && (
                  <div style={{marginTop:12}}>
                    <div style={{display:'flex', alignItems:'center', justifyContent:'space-between', gap:8}}>
                      <label>Candidates</label>
                      <div style={{display:'flex', gap:8}}>
                        <button onClick={onAIRank} disabled={aiBusy || !(selectedTask.candidates||[]).length}>
                          {aiBusy ? "Ranking..." : "AI Rank Candidates"}
                        </button>
                      </div>
                    </div>

                    {Array.isArray(aiRankings) && aiRankings.length > 0 && (
                      <div className="mini" style={{marginTop:8}}>
                        <div style={{fontWeight:600, marginBottom:6}}>AI Recommendation</div>
                        {(aiRankings || []).map((r, idx) => {
                          const candMap = Object.fromEntries((selectedTask.candidates || []).map(c => [c.user_id, c]));
                          const c = candMap[r.user_id] || {};
                          return (
                            <div key={r.user_id} className="task-item" style={{cursor:'default'}}>
                              <div style={{display:'flex', justifyContent:'space-between', alignItems:'baseline'}}>
                                <div>
                                  <b>#{idx+1}</b>{" "}
                                  <span>{c.email || r.user_id}</span>{" "}
                                  {idx === 0 && <span className="badge ok">Top Match</span>}
                                </div>
                                <div><b>Score:</b> {r.score}</div>
                              </div>
                              {r.reason && <div className="muted" style={{marginTop:6}}>{r.reason}</div>}
                            </div>
                          );
                        })}
                      </div>
                    )}

                    <div className="tasks-grid" style={{marginTop:8}}>
                      {(selectedTask.candidates || []).map(c => (
                        <div key={c.user_id} className="task-item" style={{cursor:'default'}}>
                          <div style={{display:'flex', justifyContent:'space-between', alignItems:'center', gap:8}}>
                            <div style={{flex:1}}>
                              <div><b>{c.email || c.user_id}</b></div>
                              <small className="muted">Wallet: {c.wallet} · Note: {c.note || "—"}</small>
                              {c.stats && (
                                <div className="mini" style={{marginTop:6}}>
                                  <div><b>Solved tasks:</b> {c.stats?.solved_total ?? 0}</div>
                                  <div style={{display:'flex', gap:8, flexWrap:'wrap', marginTop:6}}>
                                    {(c.stats?.topics || []).map(t => (
                                      <div key={`${c.user_id}-${t.topic}`} className="mini" style={{padding:'4px 8px'}}>
                                        <small>{t.topic}: <b>{t.count}</b></small>
                                      </div>
                                    ))}
                                    {(!c.stats || (c.stats.topics||[]).length===0) && <small className="muted">No paid history</small>}
                                  </div>
                                </div>
                              )}
                            </div>
                            <button onClick={()=>onAssign(c.user_id, c.wallet)}>Assign</button>
                          </div>
                        </div>
                      ))}
                      {(!selectedTask.candidates || selectedTask.candidates.length === 0) && <small className="muted">No candidates yet.</small>}
                    </div>
                  </div>
                )}

                {/* Timeline merged (creator & assigned solver) */}
                {(selectedTask.created_by === me._id || selectedTask.assigned_to === me._id) && (
                  <div style={{ marginTop: 16 }}>
                    <label>Timeline</label>
                    <div className="tasks-grid">
                      {mergedTimeline(selectedTask).map((ev, idx) => (
                        <div key={idx} className="task-item" style={{ cursor: 'default', borderColor: ev.type === 'review' ? '#4a2a2a' : undefined }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
                            <div><b>{ev.title}</b></div>
                            <small className="muted">{ev.ts ? new Date(ev.ts).toLocaleString() : ""}</small>
                          </div>
                          <div style={{ whiteSpace: 'pre-wrap', marginTop: 6 }}>{ev.body}</div>
                        </div>
                      ))}
                      {mergedTimeline(selectedTask).length === 0 && <small className="muted">No submissions yet.</small>}
                    </div>
                  </div>
                )}

                {/* ASSIGNED/CHANGES_REQUESTED: solver submit */}
                {(selectedTask.assigned_to === me._id) && (selectedTask.status === 'assigned' || selectedTask.status === 'changes_requested') && (
                  <div style={{ marginTop: 12 }}>
                    <label>{selectedTask.status === 'assigned' ? "Your solution" : "New revision"}</label>
                    <textarea value={solveAnswer} onChange={e => setSolveAnswer(e.target.value)} style={{ width: '100%', minHeight: 120 }} placeholder="Type your solution..." />
                    <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
                      <button onClick={onSubmitSolution}>Submit</button>
                    </div>
                  </div>
                )}

                {/* UNDER_REVIEW: creator actions */}
                {selectedTask.created_by === me._id && selectedTask.status === 'under_review' && (
                  <div style={{ marginTop: 12 }}>
                    <label>Request changes (comments)</label>
                    <textarea value={reviewComments} onChange={e => setReviewComments(e.target.value)} style={{ width: '100%', minHeight: 100 }} placeholder="What should be improved..." />
                    <div style={{ display: 'flex', gap: 8, marginTop: 8, flexWrap: 'wrap' }}>
                      <button onClick={onRequestChanges}>Request changes</button>
                      <button onClick={onApproveAndPay}>Approve & Pay</button>
                    </div>
                  </div>
                )}

                {selectedTask.status === 'paid' && (
                  <div style={{ marginTop: 12 }}>
                    <small className="ok" style={{ display: 'block' }}>
                      Paid. Tx: {selectedTask.paid_tx_hash} ·{" "}
                      <a className="muted" href={`https://testnet.xrpl.org/transactions/${selectedTask.paid_tx_hash}`} target="_blank" rel="noreferrer">Open in explorer</a>
                    </small>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
      <ConfirmUI />
      {Toasts}
    </>
  );
}