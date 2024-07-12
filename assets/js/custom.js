const tocToggleBtn = document.querySelector('#toc-toggle');
const tocToggleText = document.querySelector('#toc-toggle-text');
const toc = document.querySelector('#toc');

if (tocToggleBtn) {
    tocToggleBtn.addEventListener('click', () => {
        toc.classList.toggle('open');
        if (toc.classList.contains('open')) {
            tocToggleText.classList.remove('fa-chevron-left');
            tocToggleText.classList.add('fa-chevron-right');
        } else {
            tocToggleText.classList.remove('fa-chevron-right');
            tocToggleText.classList.add('fa-chevron-left');
        }
    });
}
