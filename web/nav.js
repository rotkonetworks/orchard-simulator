// Mobile nav toggle. Wired on every page that includes the site nav.
const toggle = document.getElementById('nav-toggle');
const inner = document.getElementById('nav-inner');
if (toggle && inner) {
  toggle.addEventListener('click', () => {
    const isOpen = inner.classList.toggle('open');
    toggle.setAttribute('aria-expanded', String(isOpen));
  });
}
