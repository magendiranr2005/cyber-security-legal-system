document.addEventListener('DOMContentLoaded', () => {
  const searchInput = document.getElementById('legalSearch');
  if (!searchInput) return;

  searchInput.addEventListener('input', (event) => {
    const term = event.target.value.trim().toLowerCase();
    document.querySelectorAll('.legal-card').forEach((card) => {
      const text = (card.textContent || '').toLowerCase();
      card.style.display = text.includes(term) ? 'block' : 'none';
    });
  });
});
