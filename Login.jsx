import React, { useEffect, useState, useRef } from "react";

/**
 * AuthLogin.jsx
 * Single-file React component for a /auth/login page.
 * - Tailwind CSS for styling
 * - Credential login flow (email + password)
 * - Social login buttons (Google, GitHub) via redirect to OAuth endpoints
 * - Client-side validation + password strength indicator
 * - reCAPTCHA v2/v3 integration (client-side token retrieval)
 * - Session persistence (localStorage + cookie fallback)
 *
 * Usage:
 *  - Place this component on /auth/login route of your React/Next.js app.
 *  - Provide environment variables or replace endpoints:
 *      RECAPTCHA_SITE_KEY (optional) -> will dynamically inject script
 *      /api/auth/login (POST) -> handles credential login, expects {email,password,recaptchaToken}
 *      /api/auth/oauth/:provider (GET) -> redirects to provider login (google, github)
 *
 * Notes:
 *  - This component does not perform server-side validation or verification of reCAPTCHA token.
 *  - On successful login it expects a JSON response with { success: true, token, user }
 *  - Customize endpoints and token handling to match your backend.
 */

const RECAPTCHA_SITE_KEY = process.env.REACT_APP_RECAPTCHA_SITE_KEY || process.env.NEXT_PUBLIC_RECAPTCHA_SITE_KEY || "";

const PasswordStrength = ({ password }) => {
  const score = getPasswordScore(password);
  const labels = ["Very weak", "Weak", "Okay", "Good", "Strong"];
  return (
    <div className="mt-2">
      <div className="h-2 w-full bg-gray-200 rounded overflow-hidden">
        <div
          className={`h-full rounded transition-all duration-200`}
          style={{ width: `${(score / 4) * 100}%`, background: strengthColor(score) }}
        />
      </div>
      <p className="text-sm mt-1 text-gray-600">{labels[Math.max(0, Math.min(4, score))]}</p>
    </div>
  );
};

function strengthColor(score) {
  switch (score) {
    case 0:
      return "#ef4444"; // red
    case 1:
      return "#f97316"; // orange
    case 2:
      return "#f59e0b"; // amber
    case 3:
      return "#10b981"; // green
    case 4:
      return "#065f46"; // dark green
    default:
      return "#e5e7eb";
  }
}

function getPasswordScore(pw) {
  if (!pw || pw.length === 0) return 0;
  let score = 0;
  if (pw.length >= 8) score++;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  return score;
}

function validateEmail(email) {
  const re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(".+"))@(([^<>()[\]\\.,;:\s@\"]+\.)+[^<>()[\]\\.,;:\s@\"]{2,})$/i;
  return re.test(String(email).toLowerCase());
}

export default function AuthLogin() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [remember, setRemember] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const recaptchaRef = useRef(null);

  // Load saved session (if any) to prefill/auto-login
  useEffect(() => {
    try {
      const saved = localStorage.getItem("auth_session");
      if (saved) {
        const obj = JSON.parse(saved);
        if (obj?.email) setEmail(obj.email);
        // optionally: auto-validate token with server here
      }
    } catch (e) {
      // ignore
    }
  }, []);

  // Inject reCAPTCHA script if site key present
  useEffect(() => {
    if (!RECAPTCHA_SITE_KEY) return;
    const id = "recaptcha-script";
    if (document.getElementById(id)) return;
    const s = document.createElement("script");
    s.id = id;
    s.src = `https://www.google.com/recaptcha/api.js?render=${RECAPTCHA_SITE_KEY}`;
    s.async = true;
    s.defer = true;
    document.body.appendChild(s);
  }, []);

  async function getRecaptchaToken() {
    if (!RECAPTCHA_SITE_KEY) return null;
    // grecaptcha may be available as a global
    if (window.grecaptcha && window.grecaptcha.execute) {
      try {
        const token = await window.grecaptcha.execute(RECAPTCHA_SITE_KEY, { action: "login" });
        return token;
      } catch (e) {
        console.warn("reCAPTCHA execute failed", e);
        return null;
      }
    }
    return null;
  }

  function persistSession(token, user) {
    // store in localStorage (and cookie fallback) - adapt to your security model
    try {
      const payload = { token, user, savedAt: Date.now() };
      if (remember) localStorage.setItem("auth_session", JSON.stringify({ email: user?.email || email, token }));
      else localStorage.removeItem("auth_session");

      // a simple cookie set (secure, httpOnly should be set on server side)
      document.cookie = `auth_token=${token}; path=/; max-age=${remember ? 60 * 60 * 24 * 30 : 60 * 60 * 4}`;
    } catch (e) {
      console.warn("persist error", e);
    }
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    setSuccess("");

    // client-side validation
    if (!validateEmail(email)) {
      setError("Please enter a valid email.");
      return;
    }
    if (password.length < 6) {
      setError("Password must be at least 6 characters.");
      return;
    }

    setLoading(true);
    let recaptchaToken = null;
    try {
      recaptchaToken = await getRecaptchaToken();
    } catch (err) {
      console.warn("reCAPTCHA error", err);
    }

    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password, recaptchaToken }),
      });
      const json = await res.json();
      if (!res.ok) {
        setError(json?.message || "Login failed. Please check your credentials.");
        setLoading(false);
        return;
      }

      if (json?.success) {
        // store token & user
        persistSession(json.token, json.user || { email });
        setSuccess("Login successful — redirecting...");
        // emulate redirect or fire event
        setTimeout(() => {
          window.location.href = json?.redirectTo || "/dashboard";
        }, 600);
      } else {
        setError(json?.message || "Login failed.");
      }
    } catch (err) {
      console.error(err);
      setError("Network error — please try again.");
    } finally {
      setLoading(false);
    }
  }

  function startOAuth(provider) {
    // Open redirect to server-side OAuth handler. You could open a popup instead and listen for postMessage.
    window.location.href = `/api/auth/oauth/${provider}`;
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-b from-white to-gray-50 p-6">
      <div className="w-full max-w-md bg-white rounded-2xl shadow-lg p-8">
        <h1 className="text-2xl font-semibold mb-2">Welcome back</h1>
        <p className="text-sm text-gray-500 mb-6">Log in to your account to continue</p>

        {error && (
          <div className="mb-4 p-3 rounded bg-red-50 text-red-700">{error}</div>
        )}
        {success && (
          <div className="mb-4 p-3 rounded bg-green-50 text-green-700">{success}</div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1">Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@company.com"
              className="w-full px-4 py-2 rounded-xl border border-gray-200 focus:outline-none focus:ring-2 focus:ring-indigo-300"
            />
          </div>

          <div>
            <label className="block text-sm font-medium mb-1">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Your strong password"
              className="w-full px-4 py-2 rounded-xl border border-gray-200 focus:outline-none focus:ring-2 focus:ring-indigo-300"
            />
            <PasswordStrength password={password} />
            <div className="flex justify-between items-center mt-2 text-xs text-gray-500">
              <label className="flex items-center gap-2">
                <input type="checkbox" checked={remember} onChange={() => setRemember(!remember)} />
                Remember me
              </label>
              <a href="/auth/forgot" className="underline">Forgot password?</a>
            </div>
          </div>

          <div>
            <button
              type="submit"
              disabled={loading}
              className="w-full py-2 rounded-xl bg-indigo-600 text-white font-semibold hover:bg-indigo-700 disabled:opacity-60 transition-colors"
            >
              {loading ? "Signing in..." : "Sign in"}
            </button>
          </div>
        </form>

        <div className="my-4 flex items-center gap-3">
          <div className="flex-1 h-px bg-gray-200" />
          <div className="text-xs text-gray-400">or continue with</div>
          <div className="flex-1 h-px bg-gray-200" />
        </div>

        <div className="grid grid-cols-2 gap-3">
          <button
            onClick={() => startOAuth("google")}
            className="flex items-center gap-2 justify-center border border-gray-200 py-2 rounded-xl hover:shadow-sm"
          >
            <svg width="18" height="18" viewBox="0 0 533.5 544.3" xmlns="http://www.w3.org/2000/svg"><path fill="#4285f4" d="M533.5 278.4c0-17.7-1.6-34.8-4.7-51.3H272v96.9h146.9c-6.4 34.6-25.5 63.9-54.4 83.6v69.1h87.8c51.4-47.3 81.2-117.3 81.2-198.3z"/><path fill="#34a853" d="M272 544.3c73.7 0 135.6-24.5 180.8-66.6l-87.8-69.1c-24.4 16.4-55.6 26.1-93 26.1-71.5 0-132-48.3-153.6-113.2H28.2v71.1C73.5 489.6 167.6 544.3 272 544.3z"/><path fill="#fbbc04" d="M118.4 327.5c-5.7-17-9-35.1-9-53.5s3.3-36.5 9-53.5V149.4H28.2C10 186.9 0 225.6 0 274c0 48.4 10 87.1 28.2 124.6l90.2-71.1z"/><path fill="#ea4335" d="M272 108.7c39.9 0 75.7 13.7 104 40.6l78-78C407.4 25.7 345.5 0 272 0 167.6 0 73.5 54.7 28.2 149.4l90.2 71.1C140 157 200.5 108.7 272 108.7z"/></svg>
            Google
          </button>

          <button
            onClick={() => startOAuth("github")}
            className="flex items-center gap-2 justify-center border border-gray-200 py-2 rounded-xl hover:shadow-sm"
          >
            <svg width="18" height="18" viewBox="0 0 16 16" fill="currentColor" xmlns="http://www.w3.org/2000/svg"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2 .37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.13 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.11.16 1.93.08 2.13.51.56.82 1.28.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.19 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>
            GitHub
          </button>
        </div>

        <p className="mt-6 text-center text-sm text-gray-500">
          Don’t have an account?{' '}
          <a href="/auth/register" className="underline">Create one</a>
        </p>

        {/* Invisible area for reCAPTCHA */}
        <div ref={recaptchaRef} style={{ height: 0, width: 0, overflow: "hidden" }} />

      </div>
    </div>
  );
}
