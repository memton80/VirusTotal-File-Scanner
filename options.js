document.getElementById('save').addEventListener('click', async () => {
  const val = document.getElementById('api').value.trim();
  await browser.storage.local.set({ vt_api_key: val });
  alert('Clé enregistrée.');
});
document.getElementById('forget').addEventListener('click', async () => {
  if (!confirm('Supprimer la clé API stockée ?')) return;
  await browser.storage.local.remove('vt_api_key');
  alert('Clé supprimée.');
});
(async ()=>{
  const s = await browser.storage.local.get('vt_api_key');
  if (s.vt_api_key) document.getElementById('api').value = s.vt_api_key;
})();