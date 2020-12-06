const allowBtn = document.querySelector('.dialog button.allow-btn');

if (allowBtn) {
  allowBtn.addEventListener('click', (e) => {
    e.preventDefault();
    const form = document.forms['consent-form'];
    form.elements.consent.value = true;
    form.submit();
  });
}
