document.addEventListener('DOMContentLoaded', function() {
  // move the cursor to the end of the value
  const input = document.querySelector('input[name="login_hint"]');
  const value = input.value;
  input.value = '';
  input.value = value;
});
