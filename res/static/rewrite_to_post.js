document.addEventListener('DOMContentLoaded', function() {
  var form = document.createElement('form');
  form.method = 'post';
  form.action = location.pathname;
  document.body.appendChild(form);

  function extract(input) {
    var params = input.slice(1);
    var re = /([^&=]+)=([^&]*)/g;
    var match;
    while (match = re.exec(params)) {
      var el = document.createElement('input');
      el.type = 'hidden';
      el.name = decodeURIComponent(match[1]);
      el.value = decodeURIComponent(match[2]);
      form.appendChild(el);
    }
  }

  extract(location.hash)
  extract(location.search)
  form.submit();
});
