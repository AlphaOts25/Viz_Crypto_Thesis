document.addEventListener("DOMContentLoaded", () => {

    // ===== DROPDOWN =====
    const dropdowns = document.querySelectorAll(".dropdown-btn");

    dropdowns.forEach(btn => {
        btn.addEventListener("click", () => {
            btn.classList.toggle("active");

            const content = btn.nextElementSibling;
            if (!content) return;

            content.style.display =
                content.style.display === "block" ? "none" : "block";
        });
    });

    // ===== SIDEBAR TOGGLE (MOBILE) =====
    const sidebar        = document.getElementById("sidebar");
    const sidebarToggle  = document.getElementById("sidebarToggle");
    const sidebarOverlay = document.getElementById("sidebarOverlay");
    const toggleIcon     = document.getElementById("toggleIcon");

    if (sidebar && sidebarToggle && sidebarOverlay && toggleIcon) {

        sidebarToggle.addEventListener("click", () => {
            sidebar.classList.toggle("open");
            sidebarOverlay.classList.toggle("active");

            toggleIcon.textContent =
                sidebar.classList.contains("open") ? "✕" : "☰";
        });

        sidebarOverlay.addEventListener("click", () => {
            sidebar.classList.remove("open");
            sidebarOverlay.classList.remove("active");
            toggleIcon.textContent = "☰";
        });
    }
});

// ===== DESKTOP SIDEBAR TOGGLE =====
function toggleSidebar() {
    const sidebar = document.querySelector(".sidebar");
    const content = document.querySelector(".content-area");

    if (!sidebar || !content) return;

    sidebar.classList.toggle("hidden");

    content.style.marginLeft =
        sidebar.classList.contains("hidden") ? "0" : "";
}