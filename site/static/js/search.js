/* Client-side search over the Zola-generated elasticlunr index.
 *
 * The index is ~300 KB, which is far too much to load on a page a reader may never search,
 * so nothing is fetched until the box is first focused. Until then this file costs one
 * event listener. There is no server and no third party: the whole thing runs in the tab.
 */
(function () {
  var input = document.getElementById("q");
  var panel = document.getElementById("results");
  if (!input || !panel) return;

  var index = null;
  var docs = null;
  var loading = null;
  var base = input.dataset.base;

  function load() {
    if (loading) return loading;
    loading = Promise.all([
      new Promise(function (resolve, reject) {
        var s = document.createElement("script");
        s.src = base + "elasticlunr.min.js";
        s.onload = resolve;
        s.onerror = reject;
        document.head.appendChild(s);
      }),
      fetch(base + "search_index.en.json").then(function (r) { return r.json(); }),
    ]).then(function (both) {
      var raw = both[1];
      index = elasticlunr.Index.load(raw);
      docs = raw.documentStore.docs;
    });
    return loading;
  }

  /* A window of body text around the first match, so a result says why it matched. */
  function snippet(body, terms) {
    var lower = body.toLowerCase();
    var at = -1;
    for (var i = 0; i < terms.length && at < 0; i++) at = lower.indexOf(terms[i]);
    if (at < 0) at = 0;
    var start = Math.max(0, at - 60);
    var text = body.slice(start, start + 180).replace(/\s+/g, " ").trim();
    return (start > 0 ? "… " : "") + text + " …";
  }

  function render(query) {
    var terms = query.toLowerCase().split(/\s+/).filter(Boolean);
    var hits = index.search(query, { bool: "AND", expand: true }).slice(0, 8);

    if (!hits.length) {
      panel.innerHTML = "<p class=\"no-hits\">No matches for “" + escapeHtml(query) + "”.</p>";
      panel.hidden = false;
      return;
    }
    panel.innerHTML = hits
      .map(function (hit) {
        var doc = docs[hit.ref];
        return (
          '<a href="' + escapeHtml(hit.ref) + '">' +
          "<strong>" + escapeHtml(doc.title) + "</strong>" +
          "<span>" + escapeHtml(snippet(doc.body, terms)) + "</span></a>"
        );
      })
      .join("");
    panel.hidden = false;
  }

  function escapeHtml(s) {
    return s.replace(/[&<>"]/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c];
    });
  }

  var timer;
  input.addEventListener("input", function () {
    var query = input.value.trim();
    clearTimeout(timer);
    if (query.length < 2) {
      panel.hidden = true;
      return;
    }
    timer = setTimeout(function () {
      load().then(function () { render(query); }).catch(function () {
        panel.innerHTML = "<p class=\"no-hits\">Search is unavailable.</p>";
        panel.hidden = false;
      });
    }, 120);
  });

  input.addEventListener("focus", load);

  /* `?q=` runs a search on load, so a result page is a URL you can share — and so the
     `SearchAction` this site declares to search engines is something it actually does. */
  var initial = new URLSearchParams(location.search).get("q");
  if (initial && initial.trim().length > 1) {
    input.value = initial;
    load().then(function () { render(initial.trim()); });
  }

  /* Arrow keys walk into the results; the links are ordinary tab stops besides. */
  input.addEventListener("keydown", function (e) {
    if (e.key === "ArrowDown" && !panel.hidden) {
      var first = panel.querySelector("a");
      if (first) {
        e.preventDefault();
        first.focus();
      }
    }
  });
  panel.addEventListener("keydown", function (e) {
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    var links = Array.prototype.slice.call(panel.querySelectorAll("a"));
    var at = links.indexOf(document.activeElement);
    if (at < 0) return;
    e.preventDefault();
    var next = at + (e.key === "ArrowDown" ? 1 : -1);
    if (next < 0) input.focus();
    else if (links[next]) links[next].focus();
  });

  /* `/` focuses the box, Escape leaves it — the shortcuts a reader already expects. */
  document.addEventListener("keydown", function (e) {
    if (e.key === "/" && document.activeElement !== input) {
      e.preventDefault();
      input.focus();
    } else if (e.key === "Escape") {
      panel.hidden = true;
      input.blur();
    }
  });

  document.addEventListener("click", function (e) {
    if (!panel.contains(e.target) && e.target !== input) panel.hidden = true;
  });
})();
