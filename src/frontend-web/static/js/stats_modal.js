function initStatsModal() {

    const modal = document.getElementById("processModal");
    const modalTitle = document.getElementById("modalTitle");
    const modalList = document.getElementById("modalList");
    const closeBtn = document.getElementById("closeModalBtn");

    if (!modal || !closeBtn) {
        console.warn("Modal no encontrado. stats.html aún no está en el DOM.");
        return;
    }

    closeBtn.onclick = () => modal.style.display = "none";

    modal.onclick = e => {
        if (e.target === modal) modal.style.display = "none";
    };

    // Delegación de eventos: funciona incluso con contenido AJAX
    document.addEventListener("click", e => {

        const link = e.target.closest(".process-link");
        if (!link) return;

        e.preventDefault();

        const proc = link.dataset.proc;
        const domains = JSON.parse(link.dataset.domains);

        modalTitle.textContent = "Dominios SNI usados por: " + proc;
        modalList.innerHTML = "";

        domains.forEach(d => {
            const li = document.createElement("li");
            li.textContent = d;
            modalList.appendChild(li);
        });

        modal.style.display = "block";
    });

    console.log("Modal inicializado correctamente");
}
