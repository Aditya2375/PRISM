
import "./Selection.css";

function Selection({ onSelect }) {
  return (
    <main className="selection-screen">
      <div className="selection-container">
        <h1>Welcome to P.R.I.S.M</h1>

        <p className="selection-subtitle">
          Select how you want to access the platform.
        </p>

        <div className="selection-options">
          <button
            className="selection-card"
            onClick={() => onSelect("User")}
          >
            <span className="selection-icon">♙</span>
            <h2>User</h2>
            <p>Access your secure workspace.</p>
          </button>

          <button
            className="selection-card"
            onClick={() => onSelect("Admin")}
          >
            <span className="selection-icon">⬡</span>
            <h2>Admin</h2>
            <p>Manage and monitor the platform.</p>
          </button>
        </div>
      </div>
    </main>
  );
}

export default Selection;
