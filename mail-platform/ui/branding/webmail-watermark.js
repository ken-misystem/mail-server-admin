let dark = window.matchMedia('(prefers-color-scheme: dark)').matches;
try {
    const preference = document.cookie.match(/(?:^|;\s*)colorMode=(dark|light)(?:;|$)/);
    if (preference) {
        dark = preference[1] === 'dark';
    }
} catch {
    // Use the system colour scheme if cookies are unavailable.
}
document.documentElement.classList.toggle('dark-mode', dark);
