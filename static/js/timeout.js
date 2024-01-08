// JavaScript to handle the session timeout
var timeoutTimer;

function resetTimeout() {
  clearTimeout(timeoutTimer);
  timeoutTimer = setTimeout(logout, 900000);
}

document.addEventListener("mousemove", resetTimeout);
document.addEventListener("keypress", resetTimeout);
document.addEventListener("click", resetTimeout);
document.addEventListener("scroll", resetTimeout);

function logout() {
  window.location.href = "/logout?timeout=true";
}

resetTimeout();
