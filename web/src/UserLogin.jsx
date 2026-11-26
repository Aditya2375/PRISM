
import { useState } from "react";
import "./UserLogin.css";

function UserLogin({ onLogin }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [errors, setErrors] = useState({});

  function handleSubmit(e) {
    e.preventDefault();

    const newErrors = {};

    if (!email.trim()) {
      newErrors.email = "Please enter your email address.";
    }

    if (!password.trim()) {
      newErrors.password = "Please enter your password.";
    }

    setErrors(newErrors);
    if (Object.keys(newErrors).length === 0) onLogin?.(email);
  }

  return (
    <main className="login-screen">
      <div className="login-container">

        <div className="login-brand">
          <div className="login-brand-header">
            <img
              src="/images/prism-emblem.png"
              alt="P.R.I.S.M prism"
              className="login-logo"
            />
            <h1>P.R.I.S.M</h1>
          </div>
        </div>

        <div className="login-card">
          <h2>User Login</h2>

          <p className="login-subtitle">
  Sign in to access your secure workspace.
</p>

          <form onSubmit={handleSubmit} noValidate>
            <div className="form-group">
              <label htmlFor="email">Email Address</label>

              <input
                type="email"
                id="email"
                placeholder="Enter your email"
                value={email}
                className={errors.email ? "input-error" : ""}
                onChange={(e) => {
                  setEmail(e.target.value);
                  setErrors((prev) => ({ ...prev, email: "" }));
                }}
              />

              {errors.email && (
                <small className="error-message">{errors.email}</small>
              )}
            </div>

            <div className="form-group">
              <label htmlFor="password">Password</label>

              <input
                type="password"
                id="password"
                placeholder="Enter your password"
                value={password}
                className={errors.password ? "input-error" : ""}
                onChange={(e) => {
                  setPassword(e.target.value);
                  setErrors((prev) => ({ ...prev, password: "" }));
                }}
              />

              {errors.password && (
                <small className="error-message">{errors.password}</small>
              )}
            </div>

            <button type="submit" className="login-button">
              <img src="/images/login-arrow.png" alt="" />
              <span>Sign In</span>
            </button>
          </form>
        </div>

      </div>
    </main>
  );
}

export default UserLogin;
