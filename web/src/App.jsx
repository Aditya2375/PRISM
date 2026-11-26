
import { useEffect, useState } from "react";
import "./App.css";
import AdminLogin from "./AdminLogin";
import UserLogin from "./UserLogin";
import Selection from "./Selection";
import UserDashboard from "./UserDashboard";
import AdminDashboard from "./AdminDashboard";

function App() {
  const [showSelection, setShowSelection] = useState(false);
  const [selectedRole, setSelectedRole] = useState("");
  const [signedInUser, setSignedInUser] = useState("");
  const [signedInAdmin, setSignedInAdmin] = useState("");

  useEffect(() => {
    const timer = setTimeout(() => {
      setShowSelection(true);
      window.history.replaceState({ page: "selection" }, "");
    }, 3500);

    return () => clearTimeout(timer);
  }, []);

  useEffect(() => {
    function handlePopState(event) {
      if (selectedRole) {
        setSelectedRole("");
      }
    }

    window.addEventListener("popstate", handlePopState);

    return () => {
      window.removeEventListener("popstate", handlePopState);
    };
  }, [selectedRole]);

  function handleRoleSelect(role) {
    window.history.pushState({ page: "login" }, "");
    setSelectedRole(role);
  }

  if (signedInUser) {
    return <UserDashboard email={signedInUser} onSignOut={() => { setSignedInUser(""); setSelectedRole(""); }} />;
  }
  if (signedInAdmin) {
    return <AdminDashboard email={signedInAdmin} onSignOut={() => { setSignedInAdmin(""); setSelectedRole(""); }} />;
  }

  return (
    <div className={`app-wrapper ${showSelection ? "show-selection" : ""} ${selectedRole ? "show-login" : ""}`}>

      <div className="intro-screen">
        <div className="intro-prism">
          <img src="/images/prism-emblem.png" alt="P.R.I.S.M emblem" />
        </div>

        <div className="intro-copy">
          <h1>P.R.I.S.M</h1>
          <p>
            Post-quantum Resilient Identity &amp; Security Management
          </p>
        </div>
      </div>

      <div className="selection-wrapper">
        <Selection onSelect={handleRoleSelect} />
      </div>

      <div className="login-wrapper">
  {selectedRole === "Admin" && <AdminLogin onLogin={setSignedInAdmin} />}
  {selectedRole === "User" && <UserLogin onLogin={setSignedInUser} />}
</div>

    </div>
  );
}

export default App;
