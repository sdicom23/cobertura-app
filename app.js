/* Mini app de cobertura AT&T — sólo funciona abierta desde el bot de Telegram.
   Las capas están cifradas (AES-256-CTR); la llave la entrega el Apps Script tras validar la firma de Telegram. */
(function () {
  'use strict';
  const q = new URLSearchParams(location.search);
  const API = q.get('api') || '';
  const BASE = 'https://tiles.openfreemap.org/styles/positron';
  const ARCH = {
    '4g': [{ u: 'datos/att4g_low.bin', n: '8a96e867a112cc99', max: 9 }, { u: 'datos/att4g_high.bin', n: 'e5a79fc924d533e9', min: 9 }],
    '3g': [{ u: 'datos/att3g_low.bin', n: '8b3ee74cc683734e', max: 9 }, { u: 'datos/att3g_high.bin', n: '7ce86913f65cf8ec', min: 9 }]
  };
  const SIN = { k: 'sin', e: 'Sin cobertura', c: '#8b0000',
    t: ['No hay transmisión; el equipo debe guardar posiciones (buffer) y enviarlas al recuperar señal.', 'Sin servicio AT&T.', 'Si el tramo es crítico, considera SIM multi-operador o respaldo satelital.'] };
  const NIV = {
    '4g': [
      { k: 'alta', r: 4, e: 'Alta (≥ -100 dBm)', c: '#1a9850', t: ['Funciona sin problema, con reportes en tiempo real.', 'Estables, incluso dentro de la cabina y en interiores.', 'Cualquier equipo con antena interna trabaja bien.'] },
      { k: 'media', r: 3, e: 'Media (-111 a -100 dBm)', c: '#d9b81f', t: ['Funciona bien; en interiores puede haber algún reintento ocasional.', 'Estables en exteriores; en sótanos, edificios o cabinas blindadas puede bajar la calidad.', 'La antena interna suele bastar; para equipos fijos en interior conviene antena externa.'] },
      { k: 'baja', r: 2, e: 'Baja (-121 a -111 dBm)', c: '#f46d43', t: ['Normalmente funciona, aunque puede haber reintentos o reportes atrasados.', 'Pueden fallar, sobre todo dentro de la cabina o con antenas de poca ganancia.', 'Un equipo con antena externa o con LTE B28/700 MHz responde mejor ahí.'] },
      { k: 'extendida', r: 1, e: 'Extendida (CobEx)', c: '#4f8fc0', t: ['Funciona en exteriores con reintentos frecuentes; usa un equipo con buffer para no perder reportes.', 'Poco confiables; son probables los cortes.', 'Antena externa de buena ganancia y equipo con LTE B28/700 MHz.'] },
      { k: 'extendida_alt', r: 1, e: 'Extendida alterna', c: '#9ec3e0', t: ['Posible en exteriores, sin garantía; espera reportes atrasados.', 'Es muy probable que fallen.', 'Antena externa y buffer en el equipo; no se recomienda para equipos en interior.'] }
    ],
    '3g': [
      { k: 'alta', r: 4, e: 'Alta (RSCP > -85 dBm)', c: '#1a9850', t: ['Funciona sin problema en equipos con 3G (UMTS). Equipos sólo LTE (LTE-M, Cat-1) no se conectan en 3G.', 'Estables, incluso dentro de la cabina y en interiores.', 'Confirma que el equipo soporte 3G y la banda de AT&T.'] },
      { k: 'media', r: 3, e: 'Media (-96 a -85 dBm)', c: '#d9b81f', t: ['Funciona bien en equipos 3G; en interiores puede haber algún reintento.', 'Estables en exteriores; en sótanos o cabinas blindadas puede bajar la calidad.', 'Antena interna suele bastar; equipos sólo LTE no funcionan en 3G.'] },
      { k: 'baja', r: 2, e: 'Baja (-116 a -96 dBm)', c: '#f46d43', t: ['Normalmente funciona en equipos 3G, aunque puede haber reintentos o reportes atrasados.', 'Pueden fallar, sobre todo dentro de la cabina o con antenas de poca ganancia.', 'Un equipo 3G con antena externa responde mejor ahí.'] },
      { k: 'extendida', r: 1, e: 'Extendida (CobEx)', c: '#4f8fc0', t: ['Sólo equipos 3G; funciona en exteriores con reintentos frecuentes. Usa buffer para no perder reportes.', 'Poco confiables; son probables los cortes.', 'Antena externa de buena ganancia; equipos sólo LTE no funcionan aquí.'] }
    ]
  };
  const NOMBRE = { '4g': 'AT&T 4G', '3g': 'AT&T 3G' };
  const $ = id => document.getElementById(id);
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  const tg = window.Telegram && window.Telegram.WebApp;
  const initData = tg ? tg.initData : '';
  if (tg) { tg.ready(); tg.expand(); }
  let tec = q.get('tec') === '3g' ? '3g' : '4g';
  let llave = null, marcador = null, ruta = null, puntosRuta = [];

  /* Ocultar / mostrar los paneles para ver todo el mapa */
  const ocultar = () => document.body.classList.add('oculto');
  const mostrar = () => document.body.classList.remove('oculto');
  function velo(html) { $('velo').innerHTML = html; $('velo').style.display = 'flex'; }
  async function api(body) {
    if (!API) throw new Error('sin api');
    const r = await fetch(API, { method: 'POST', body: JSON.stringify(Object.assign({ initData }, body)) });
    return r.json();
  }

  /* ---------- Fuente PMTiles cifrada (AES-CTR permite descifrar cualquier rango) ---------- */
  const hex = h => new Uint8Array(h.match(/../g).map(x => parseInt(x, 16)));
  class FuenteCifrada {
    constructor(url, nonce, key) { this.url = new URL(url, location.href).href; this.nonce = hex(nonce); this.key = key; }
    getKey() { return this.url; }
    async getBytes(offset, length, signal) {
      const ini = Math.floor(offset / 16) * 16, fin = offset + length;
      const r = await fetch(this.url, { headers: { Range: 'bytes=' + ini + '-' + (fin - 1) }, signal });
      if (r.status !== 206 && r.status !== 200) throw new Error('HTTP ' + r.status);
      let buf = await r.arrayBuffer();
      if (r.status === 200) buf = buf.slice(ini, fin);
      const ctr = new Uint8Array(16); ctr.set(this.nonce, 0);
      let b = BigInt(ini / 16);
      for (let i = 15; i >= 8; i--) { ctr[i] = Number(b & 0xffn); b >>= 8n; }
      const dec = await crypto.subtle.decrypt({ name: 'AES-CTR', counter: ctr, length: 64 }, this.key, buf);
      return { data: dec.slice(offset - ini, offset - ini + length) };
    }
  }

  /* ---------- Mapa ---------- */
  const protocol = new pmtiles.Protocol();
  maplibregl.addProtocol('pmtiles', protocol.tile);
  const lat0 = parseFloat(q.get('lat')), lon0 = parseFloat(q.get('lon'));
  const map = new maplibregl.Map({ container: 'map', style: BASE,
    center: isNaN(lat0) ? [-102.5, 23.6] : [lon0, lat0], zoom: isNaN(lat0) ? 4.6 : 11,
    attributionControl: { compact: true }, dragRotate: false, pitchWithRotate: false });
  map.addControl(new maplibregl.NavigationControl({ showCompass: false }), 'top-right');

  function mejorarEtiquetas() {
    (map.getStyle().layers || []).forEach(l => {
      if (l.type !== 'symbol') return;
      const sl = l['source-layer'] || '';
      try {
        if (sl === 'transportation_name') {
          const menor = /minor|path|service|track/i.test(l.id);
          map.setLayerZoomRange(l.id, menor ? 10 : 8, l.maxzoom || 24);
          map.setLayoutProperty(l.id, 'text-size', ['interpolate', ['linear'], ['zoom'], 8, menor ? 9 : 10, 12, menor ? 11 : 12, 14, menor ? 12 : 13, 17, 15]);
        }
        if (sl === 'transportation_name' || sl === 'place' || sl === 'poi') {
          map.setPaintProperty(l.id, 'text-color', '#222');
          map.setPaintProperty(l.id, 'text-halo-color', 'rgba(255,255,255,0.95)');
          map.setPaintProperty(l.id, 'text-halo-width', 1.6);
        }
      } catch (e) { }
    });
  }
  const color = t => ['match', ['get', 'cat'], ...NIV[t].flatMap(n => [n.k, n.c]), '#9aa0a6'];
  const capas = { '4g': [], '3g': [] };

  function agregarCapas(key) {
    const sym = (map.getStyle().layers || []).find(l => l.type === 'symbol');
    ['4g', '3g'].forEach(t => ARCH[t].forEach((a, i) => {
      const src = new FuenteCifrada(a.u, a.n, key);
      protocol.add(new pmtiles.PMTiles(src));
      const id = 'c_' + t + '_' + i;
      map.addSource(id, { type: 'vector', url: 'pmtiles://' + src.getKey() });
      const capa = { id, type: 'fill', source: id, 'source-layer': 'cobertura',
        layout: { visibility: t === tec ? 'visible' : 'none' },
        paint: { 'fill-color': color(t), 'fill-opacity': 0.45, 'fill-antialias': false } };
      if (a.min !== undefined) capa.minzoom = a.min;
      if (a.max !== undefined) capa.maxzoom = a.max;
      map.addLayer(capa, sym ? sym.id : undefined);
      capas[t].push(id);
    }));
  }
  function mostrarTec() {
    ['4g', '3g'].forEach(t => capas[t].forEach(id => map.setLayoutProperty(id, 'visibility', t === tec ? 'visible' : 'none')));
    $('leyenda').innerHTML = NIV[tec].map(n => `<span class="ley"><span class="sq" style="background:${n.c}"></span>${esc(n.e.split(' (')[0])}</span>`).join('') +
      `<span class="ley"><span class="sq" style="background:${SIN.c}"></span>Sin cobertura</span>`;
  }
  function botonesTec() {
    ['4g', '3g'].forEach(t => {
      const b = document.createElement('button');
      b.className = 'btn' + (t === tec ? ' on' : ''); b.textContent = NOMBRE[t];
      b.onclick = () => {
        tec = t; document.querySelectorAll('#tecs .btn').forEach(x => x.classList.toggle('on', x === b));
        mostrarTec();
        if (ruta) cuandoListo(evaluarRuta); else if (marcador) ponerPunto(marcador.getLngLat().toArray());
      };
      $('tecs').appendChild(b);
    });
  }
  function cuandoListo(fn) { map.once('idle', fn); map.triggerRepaint(); }

  /* Código de la rejilla del servidor (0-5) → nivel del mapa */
  function nivelCodigo(c) {
    const k = { 5: 'alta', 4: 'media', 3: 'baja', 2: 'extendida', 1: tec === '4g' ? 'extendida_alt' : 'extendida' }[c];
    return NIV[tec].find(n => n.k === k) || SIN;
  }
  function nivelEn(lngLat) {
    const fs = map.queryRenderedFeatures(map.project(lngLat), { layers: capas[tec].filter(id => map.getLayer(id)) });
    let mejor = null;
    fs.forEach(f => { const n = NIV[tec].find(x => x.k === f.properties.cat); if (n && (!mejor || n.r > mejor.r)) mejor = n; });
    return mejor || SIN;
  }
  function tipHTML(n, titulo) {
    return `<div class="tip"><b>💡 ${esc(titulo)} — Qué esperar en campo:</b><ul>` +
      `<li><b>Telemetría IoT (GPS, LTE-M, mensajes cortos):</b> ${esc(n.t[0])}</li>` +
      `<li><b>Llamadas y datos de celular:</b> ${esc(n.t[1])}</li><li><b>En la práctica:</b> ${esc(n.t[2])}</li></ul></div>`;
  }

  /* ---------- Punto ---------- */
  function ponerPunto([x, y]) {
    mostrar();
    if (marcador) marcador.remove();
    marcador = new maplibregl.Marker({ color: '#E24B4A' }).setLngLat([x, y]).addTo(map);
    cuandoListo(() => {
      const n = nivelEn([x, y]);
      $('info').innerHTML = `<div class="sub">${y.toFixed(5)}, ${x.toFixed(5)}</div>` +
        `<span class="sq" style="background:${n.c}"></span> <b>${NOMBRE[tec]}</b> · ${esc(n.e)}` + tipHTML(n, n.e);
    });
  }

  /* ---------- Ruta ---------- */
  const dist = (a, b) => { const R = 6371, r = Math.PI / 180, dLa = (b[1] - a[1]) * r, dLo = (b[0] - a[0]) * r;
    const x = Math.sin(dLa / 2) ** 2 + Math.cos(a[1] * r) * Math.cos(b[1] * r) * Math.sin(dLo / 2) ** 2; return 2 * R * Math.asin(Math.sqrt(x)); };
  async function pedirRuta(o, d) {
    mostrar();
    $('info').innerHTML = 'Calculando ruta…';
    let res;
    try { res = await api({ a: 'ruta', o, d }); } catch (e) { $('info').textContent = '❌ No se pudo calcular la ruta.'; return; }
    if (!res.ok) { $('info').textContent = '❌ ' + (res.msg || 'No se pudo calcular la ruta.'); return; }
    if (marcador) { marcador.remove(); marcador = null; }
    ruta = res;
    const co = res.pts.map(p => [p[1], p[0]]);
    puntosRuta = []; let acc = 0;
    for (let i = 1; i < co.length; i++) {
      const dd = dist(co[i - 1], co[i]);
      puntosRuta.push({ a: co[i - 1], b: co[i], km: dd, m: [(co[i - 1][0] + co[i][0]) / 2, (co[i - 1][1] + co[i][1]) / 2], i: i - 1 });
      acc += dd;
    }
    if (!map.getSource('ruta')) {
      map.addSource('ruta', { type: 'geojson', data: { type: 'FeatureCollection', features: [] } });
      map.addLayer({ id: 'ruta-b', type: 'line', source: 'ruta', layout: { 'line-cap': 'round', 'line-join': 'round' }, paint: { 'line-color': '#fff', 'line-width': 8 } });
      map.addLayer({ id: 'ruta-l', type: 'line', source: 'ruta', layout: { 'line-cap': 'round', 'line-join': 'round' }, paint: { 'line-color': ['get', 'c'], 'line-width': 5 } });
    }
    (window._mr || []).forEach(m => m.remove());
    window._mr = [new maplibregl.Marker({ color: '#185FA5' }).setLngLat(co[0]).addTo(map),
                  new maplibregl.Marker({ color: '#E24B4A' }).setLngLat(co[co.length - 1]).addTo(map)];
    const lons = co.map(p => p[0]), lats = co.map(p => p[1]);
    map.fitBounds([[Math.min(...lons), Math.min(...lats)], [Math.max(...lons), Math.max(...lats)]], { padding: { top: 170, bottom: 190, left: 30, right: 30 }, duration: 0 });
    cuandoListo(evaluarRuta);
  }
  function evaluarRuta() {
    if (!ruta) return;
    const km = {}; NIV[tec].forEach(n => km[n.k] = 0); km.sin = 0;
    let tramos = 0, prev = null;
    const feats = puntosRuta.map(p => {
      const cods = tec === '4g' ? ruta.c4 : ruta.c3;
      const n = cods ? nivelCodigo(Math.max(cods[p.i] || 0, cods[p.i + 1] || 0)) : nivelEn(p.m); km[n.k] += p.km;
      if (n === SIN && prev !== SIN) tramos++; prev = n;
      return { type: 'Feature', properties: { c: n.c }, geometry: { type: 'LineString', coordinates: [p.a, p.b] } };
    });
    map.getSource('ruta').setData({ type: 'FeatureCollection', features: feats });
    const tot = puntosRuta.reduce((s, p) => s + p.km, 0), pct = v => (100 * v / tot);
    const f = v => v < 10 ? v.toFixed(1) : v.toFixed(0);
    const orden = [...NIV[tec], SIN];
    const peor = [...orden].reverse().find(n => km[n.k] >= 1 && !['alta', 'media'].includes(n.k)) || orden.find(n => km[n.k] > 0);
    const sg = ruta.seg || 0, h = Math.floor(sg / 3600), mi = Math.round(sg % 3600 / 60);
    $('info').innerHTML = `<b>🛣️ ${esc(ruta.desde)} → ${esc(ruta.hasta)}</b><br>` +
      `<span class="sub">${ruta.km.toFixed(0)} km${sg ? ' · ' + (h ? h + ' h ' : '') + mi + ' min' : ''} · ${NOMBRE[tec]}: <b>${Math.round(100 - pct(km.sin))}% con cobertura</b></span>` +
      `<div class="barra">${orden.map(n => `<span style="width:${pct(km[n.k]).toFixed(1)}%;background:${n.c}"></span>`).join('')}</div>` +
      `<span class="sub">${orden.filter(n => km[n.k] >= 0.05).map(n => `<span class="sq" style="background:${n.c}"></span> ${f(km[n.k])} km`).join(' · ')}` +
      `${km.sin >= 0.05 ? ` (${tramos} tramo${tramos > 1 ? 's' : ''} sin señal)` : ''}</span>` +
      (peor ? tipHTML(peor, peor.e + (peor.k !== 'alta' && peor.k !== 'media' ? ' · ' + f(km[peor.k]) + ' km' : '')) : '');
  }

  /* ---------- Arranque ---------- */
  map.on('load', async () => {
    mejorarEtiquetas();
    botonesTec(); mostrarTec();
    if (!initData || !API) {
      velo('🔒 <div>Este mapa sólo funciona abierto desde el bot de Telegram para clientes autorizados.</div>');
      $('info').textContent = 'Ábrelo desde el bot.'; return;
    }
    let res;
    try { res = await api({ a: 'llave' }); } catch (e) { velo('No se pudo conectar. Intenta de nuevo.'); return; }
    if (!res.ok) { velo('🔒 <div>' + esc(res.msg || 'Acceso no autorizado.') + '</div>'); return; }
    $('quien').textContent = res.nombre || '';
    llave = await crypto.subtle.importKey('raw', hex(res.key), { name: 'AES-CTR' }, false, ['decrypt']);
    res.key = null;
    agregarCapas(llave);
    mostrarTec();
    $('info').textContent = 'Toca el mapa para ver la cobertura en ese punto.';
    const o = q.get('o'), d = q.get('d');
    if (o && d) pedirRuta(o, d);
    else if (!isNaN(lat0)) ponerPunto([lon0, lat0]);
  });
  let avisoCapas = false;
  map.on('error', e => {
    if (avisoCapas || !e.sourceId || !/^c_/.test(e.sourceId)) return;
    avisoCapas = true; mostrar();
    $('info').innerHTML = '⚠️ No se pudieron cargar las capas de cobertura. Cierra y vuelve a abrir el mapa; si sigue, avisa a tu asesor.';
    console.warn(e.error);
  });
  map.on('click', e => { if (!llave) return; ruta = null; if (map.getSource('ruta')) map.getSource('ruta').setData({ type: 'FeatureCollection', features: [] });
    (window._mr || []).forEach(m => m.remove()); ponerPunto([e.lngLat.lng, e.lngLat.lat]); });
  $('bOcultar').onclick = ocultar;
  $('verInfo').onclick = mostrar;
  $('bRuta').onclick = () => $('fRuta').classList.toggle('on');
  $('bIr').onclick = () => { const o = $('iO').value.trim(), d = $('iD').value.trim(); if (o && d && llave) { $('fRuta').classList.remove('on'); pedirRuta(o, d); } };
  $('bYo').onclick = () => {
    if (!navigator.geolocation || !llave) return;
    navigator.geolocation.getCurrentPosition(p => { const c = [p.coords.longitude, p.coords.latitude]; map.jumpTo({ center: c, zoom: 12 }); ponerPunto(c); },
      () => { $('info').textContent = 'No se pudo obtener tu ubicación.'; }, { enableHighAccuracy: true, timeout: 10000 });
  };
  document.addEventListener('contextmenu', e => e.preventDefault());
})();
