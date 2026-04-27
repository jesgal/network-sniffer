// ===============================
// Auto-scroll del terminal
// ===============================
window.addEventListener("load", () => {
    const terminalContainer = document.getElementById("terminal-container");
    if (terminalContainer) {
        terminalContainer.scrollTop = 0;
    }
});


// ===============================
// Cargar contenido dinámico (AJAX)
// ===============================
function loadContent(url) {
    fetch(url)
        .then(response => response.text())
        .then(html => {
            const container = document.getElementById("dynamic-content");
            container.innerHTML = html;

            // 🔥 MUY IMPORTANTE:
            // Inicializar el modal después de insertar stats.html
            if (typeof initStatsModal === "function") {
                initStatsModal();
            }

            // Mantener tu scroll si existe terminal
            setTimeout(() => {
                const terminal = document.getElementById("terminal-container");
                if (terminal) {
                    terminal.scrollTop = 0;
                }
            }, 50);
        })
        .catch(err => {
            document.getElementById("dynamic-content").innerHTML =
                "<div class='alert alert-danger'>Error cargando contenido</div>";
        });
}



// ===============================
// Delegación de eventos para enlaces .load-link
// ===============================
document.addEventListener("DOMContentLoaded", () => {

    document.body.addEventListener("click", function (e) {
        const link = e.target.closest(".load-link");
        if (!link) return;

        e.preventDefault();
        const url = link.dataset.url;
        loadContent(url);
    });

});


// ===============================
// Menús colapsables del sidebar
// ===============================
document.addEventListener("DOMContentLoaded", () => {

    document.querySelectorAll(".collapsible-header").forEach(header => {
        header.addEventListener("click", () => {
            const target = document.querySelector(header.dataset.target);
            const icon = header.querySelector("i");

            if (target.classList.contains("show")) {
                target.classList.remove("show");
                icon.classList.replace("bi-chevron-down", "bi-chevron-right");
            } else {
                target.classList.add("show");
                icon.classList.replace("bi-chevron-right", "bi-chevron-down");
            }
        });
    });

});


document.addEventListener('DOMContentLoaded', () => {
    const searchForm = document.getElementById('search-form');
    const searchInput = document.getElementById('search-input');
    const resultsContainer = document.getElementById('dynamic-content');

    searchForm.addEventListener('submit', async (e) => {
        e.preventDefault(); // Evita que la página se recargue
        
        const query = searchInput.value;
        if (!query) return;

        try {
            // Ajusta la URL '/search' según tu API backend
            const response = await fetch(`/search?q=${encodeURIComponent(query)}`);
            const data = await response.text();

            resultsContainer.innerHTML = data;
        } catch (error) {
            console.error('Error en la búsqueda:', error);
            resultsContainer.innerHTML = '<p class="text-danger">'+error+'</p>';
        }
    });
});