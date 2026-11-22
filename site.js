/* ShanX13 AiGG Direct Commander | Independent marketing presentation.
 * No demo values are live; no credentials, payment capture or device access. */
(() => {
  "use strict";
  const menu = document.querySelector("#mainMenu");
  const toggle = document.querySelector("#menuToggle");
  toggle?.addEventListener("click", () => {
    const expanded = toggle.getAttribute("aria-expanded") !== "true";
    toggle.setAttribute("aria-expanded", String(expanded));
    menu?.classList.toggle("is-open", expanded);
  });
  menu?.querySelectorAll("a").forEach(link => link.addEventListener("click", () => {
    menu.classList.remove("is-open");
    toggle?.setAttribute("aria-expanded", "false");
  }));
  const capabilities = {
    files: {n:"01",title:"Work with your actual files.",text:"Find, inspect, organize, and edit files inside approved directories. Preserve originals and demand a reversible plan for impactful changes.",bullets:["Scoped file visibility","Change review and rollback","Evidence-backed results"],terminal:"> select_device --authorized\nscope: selected account + device\n\n> inspect_files --read-only\nstatus: waiting for connected device\n\n> proof_gate\nUNKNOWN remains UNKNOWN\nNo action was executed."},
    terminal: {n:"02",title:"Run only what you approve.",text:"Issue bounded terminal operations, inspect running processes, and keep clear results with explicit authorization and device identity.",bullets:["Bounded process controls","Explicit owner authorization","Separate exit code from acceptance"],terminal:"> prepare_command --read-only\noperation: process_inventory\n\n> authorization_check\nmode: owner approval required\n\n> execute\nNOT EXECUTED — illustrative preview"},
    devices: {n:"03",title:"Keep every device in its own lane.",text:"Each authorized machine has independent enrollment, identity, capability scope and revocation. A public product must never expose private owner infrastructure.",bullets:["Device-specific credentials","Owner STOP takes precedence","Accounts and tenants remain separate"],terminal:"> device_inventory\nstatus: no live API connected\n\n> verify_device_enrollment\nresult: awaiting authenticated pairing\n\nNo real machines were contacted."},
    usage: {n:"04",title:"Get the numbers that matter.",text:"See authenticated request records, actual usage counts, account-level cost reporting, and evidence trails rather than guesses or simulated completion.",bullets:["Recorded request and result events","Usage grouped by authorized tenant","Receipt-driven audit history"],terminal:"> request_usage --verified-source\nsource: authenticated production event DB\n\n> response\nNOT CONNECTED\n\nNo activity figures have been fabricated."}
  };
  const tabs = [...document.querySelectorAll("[data-cap]")];
  function setCapability(id) {
    const d = capabilities[id];
    if (!d) return;
    tabs.forEach(el => el.setAttribute("aria-selected", String(el.dataset.cap === id)));
    document.querySelector("#capNumber").textContent = "CAPABILITY / " + d.n;
    document.querySelector("#capTitle").textContent = d.title;
    document.querySelector("#capText").textContent = d.text;
    document.querySelector("#capBullets").replaceChildren(...d.bullets.map(label => {
      const div = document.createElement("div");
      div.textContent = label;
      return div;
    }));
    document.querySelector("#capTerminal").textContent = d.terminal;
  }
  tabs.forEach(tab => tab.addEventListener("click", () => setCapability(tab.dataset.cap)));
  const year = document.querySelector("#year");
  if (year) year.textContent = String(new Date().getFullYear());
})();
