(() => {
  "use strict";

  // Mobile navigation
  const toggle = document.querySelector("[data-nav-toggle]");
  const menu = document.querySelector("[data-nav-menu]");
  if (toggle && menu) {
    toggle.addEventListener("click", () => {
      const open = menu.classList.toggle("is-open");
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
    });
  }

  // Scroll reveal
  const reveals = document.querySelectorAll(".reveal");
  if ("IntersectionObserver" in window) {
    const io = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add("is-visible");
            io.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.12 }
    );
    reveals.forEach((el) => io.observe(el));
  } else {
    reveals.forEach((el) => el.classList.add("is-visible"));
  }

  // Copy AI output
  document.querySelectorAll("[data-copy-target]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const target = document.querySelector(btn.getAttribute("data-copy-target"));
      if (!target) return;
      try {
        await navigator.clipboard.writeText(target.textContent || "");
        const previous = btn.textContent;
        btn.textContent = "Copied";
        setTimeout(() => {
          btn.textContent = previous;
        }, 1500);
      } catch (_err) {
        btn.textContent = "Copy failed";
      }
    });
  });

  // Auto-save for existing stories
  const form = document.getElementById("story-form");
  const statusEl = document.getElementById("save-status");
  if (form && form.dataset.autosave === "true") {
    let timer = null;
    let saving = false;

    const csrf =
      form.querySelector('input[name="csrf_token"]')?.value ||
      "";

    const save = async () => {
      if (saving) return;
      saving = true;
      if (statusEl) statusEl.textContent = "Saving…";

      const body = new FormData(form);
      body.set("autosave", "1");

      try {
        const res = await fetch(form.action, {
          method: "POST",
          headers: {
            "X-Requested-With": "XMLHttpRequest",
            "X-CSRFToken": csrf,
          },
          body,
        });
        const data = await res.json().catch(() => ({}));
        if (res.ok && data.ok) {
          if (statusEl) {
            statusEl.textContent = `Auto-saved ${data.updated_at || ""}`.trim();
          }
        } else if (statusEl) {
          statusEl.textContent = data.error || "Auto-save failed";
        }
      } catch (_err) {
        if (statusEl) statusEl.textContent = "Auto-save failed (offline?)";
      } finally {
        saving = false;
      }
    };

    const schedule = () => {
      clearTimeout(timer);
      timer = setTimeout(save, 1400);
    };

    form.querySelectorAll("input, select, textarea").forEach((field) => {
      field.addEventListener("input", schedule);
      field.addEventListener("change", schedule);
    });
  }
})();
