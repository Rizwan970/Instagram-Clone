// static/script.js
// Global shared JS — loaded on every page.
// NOTE: Page-specific handlers (tweet form, comment, like) live in their
//       own inline <script> blocks so they only run where needed.
//       Do NOT add a tweet form handler here — it already exists in feed.html.

document.addEventListener("DOMContentLoaded", function () {

    // ── Create Post Modal (legacy IDs kept for compatibility) ──
    const openBtn = document.getElementById("openCreateModal");
    const closeBtn = document.getElementById("closeModal");
    const modal = document.getElementById("createPostModal");

    if (openBtn && modal) {
        openBtn.onclick = () => {
            modal.style.display = "flex";
        };
    }

    if (closeBtn && modal) {
        closeBtn.onclick = () => {
            modal.style.display = "none";
        };
    }

    // ── Create Post Form ───────────────────────────────────────
    // Only attach if the form exists AND no inline handler is already set.
    const createPostForm = document.getElementById("createPostForm");
    if (createPostForm && !createPostForm.dataset.handled) {
        createPostForm.dataset.handled = "true"; // prevent double-binding
        let submitting = false;

        createPostForm.addEventListener("submit", async function (e) {
            e.preventDefault();
            e.stopImmediatePropagation();
            if (submitting) return;
            submitting = true;

            const btn = this.querySelector('button[type="submit"]');
            if (btn) btn.disabled = true;

            try {
                const response = await fetch("/api/post", {
                    method: "POST",
                    body: new FormData(this),
                    credentials: "same-origin"
                });
                if (response.ok) {
                    location.reload();
                } else {
                    alert("Post upload failed");
                }
            } catch {
                alert("Error uploading post");
            } finally {
                submitting = false;
                if (btn) btn.disabled = false;
            }
        });
    }

});

// ── Report Post (used on feed) ─────────────────────────────────
function reportPost(postId) {
    const reason = prompt("Why are you reporting this post?");
    if (!reason) return;
    fetch(`/report/${postId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason })
    })
    .then(() => alert("Report submitted 🚩"));
}