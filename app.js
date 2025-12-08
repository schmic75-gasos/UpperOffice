async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

document.getElementById('btn-scan').onclick = async () => {
  setStatus('Starting scan... (this may take a while)');
  try {
    await api('/api/scan');
    setStatus('Scan finished.');
    loadDups();
  } catch (err) {
    setStatus('Error: '+err.message);
  }
};

document.getElementById('btn-refresh').onclick = loadDups;

function setStatus(s) { document.getElementById('status').innerText = s; }

async function loadDups() {
  setStatus('Loading duplicates...');
  try {
    const groups = await api('/api/dups');
    const container = document.getElementById('dups');
    container.innerHTML = '';
    if (!groups.length) return setStatus('No duplicates found.');
    setStatus(`Found ${groups.length} duplicate groups.`);
    groups.forEach(g => {
      const div = document.createElement('div');
      div.className = 'group';
      div.innerHTML = `<strong>SHA1:</strong> ${g.sha1} — <span class="small">${g.files.length} files</span>`;
      g.files.forEach(f => {
        const fdiv = document.createElement('div');
        fdiv.className = 'file';
        fdiv.innerHTML = `<div><div>${f.path}</div><div class="small">${f.size} B • ${new Date(f.mtime).toLocaleString()}</div></div>
          <div><button data-path="${f.path}">Delete</button></div>`;
        div.appendChild(fdiv);
      });
      container.appendChild(div);
    });

    document.querySelectorAll('button[data-path]').forEach(b => {
      b.onclick = async (e) => {
        if (!confirm('Smazat: ' + b.dataset.path + ' ?')) return;
        try {
          await api('/api/delete', { method: 'POST', headers: {'content-type':'application/json'}, body: JSON.stringify({ path: b.dataset.path })});
          setStatus('Deleted '+b.dataset.path);
          loadDups();
        } catch (err) { setStatus('Error: '+err.message) }
      }
    });

  } catch (err) {
    setStatus('Error: '+err.message);
  }
}
