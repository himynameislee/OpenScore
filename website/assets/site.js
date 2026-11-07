// Copy buttons on command blocks. The page works without this script.
document.querySelectorAll("pre.cmd").forEach((pre) => {
  if (!navigator.clipboard) return;
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "copy";
  btn.textContent = "Copy";
  btn.setAttribute("aria-label", "Copy commands");
  btn.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(pre.querySelector("code").innerText.trim());
      btn.textContent = "Copied";
    } catch (_) {
      btn.textContent = "Copy failed";
    }
    setTimeout(() => { btn.textContent = "Copy"; }, 2000);
  });
  pre.classList.add("has-copy");
  pre.appendChild(btn);
});
