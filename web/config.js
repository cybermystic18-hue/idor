// build-time config (accidentally bundled into public assets in this demo)
// NOTE: in a secure deployment this would never be exposed client-side.
window.__OP_CONFIG = {
  // not well-hidden secret used to sign session tokens
  // (this simulates a real-world accidental leak a player must discover)
  SECRET_LEAK: "c0mpl3x_but_leaked_secret_2025!"
};
