function togglePassword(id, btn) {
  const input = document.getElementById(id)

  if (input.type === "password") {
    input.type = "text"
    btn.innerHTML = '<i data-lucide="eye-off"></i>'
  } else {
    input.type = "password"
    btn.innerHTML = '<i data-lucide="eye"></i>'
  }

  lucide.createIcons()
}

lucide.createIcons()
