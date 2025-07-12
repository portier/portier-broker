document.querySelector('input[name="code"]').addEventListener('paste', function(ev) {
  ev.preventDefault();
  this.value = ev.clipboardData.getData('text/plain').trim()
});
form.addEventListener('submit', function(ev) {
  ev.target.querySelector('button[type="submit"]').disabled = true;
});
