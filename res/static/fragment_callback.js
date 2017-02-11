document.addEventListener('DOMContentLoaded', function() {
  var form = document.getElementById('form');
  var params = location.hash.slice(1);
  var re = /([^&=]+)=([^&]*)/g;
  var match;
  while (match = re.exec(params)) {
    var el = document.createElement('input');
    el.type = 'hidden';
    el.name = decodeURIComponent(match[1]);
    el.value = decodeURIComponent(match[2]);
    form.appendChild(el);
  }
  form.submit();
});
