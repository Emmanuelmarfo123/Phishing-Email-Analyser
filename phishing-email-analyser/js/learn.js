/*
 * learn.js — the awareness Challenge and the personalised Training plan.
 */
(function () {
  'use strict';
  const P = window.PEA;
  const { h } = P;
  const $ = id => document.getElementById(id);
  const ITEMS = P.CHALLENGE;
  let idx = null;

  // ══════════ Challenge ══════════
  function firstUnanswered() {
    const a = P.store.get().challenge.answers;
    const i = ITEMS.findIndex(c => !a[c.id]);
    return i === -1 ? ITEMS.length : i;
  }

  function renderChallenge() {
    const answers = P.store.get().challenge.answers;
    if (idx === null) idx = firstUnanswered();
    const answered = Object.keys(answers).length;
    if (!answered && idx >= ITEMS.length) idx = 0;
    $('challenge-progress').textContent = `${answered} / ${ITEMS.length}`;
    const area = $('challenge-area');

    const dots = h('div', { class: 'dots', 'aria-label': 'Questions' }, ITEMS.map((c, i) => {
      const a = answers[c.id];
      return h('button', { type: 'button', class: [a ? (a.correct ? 'right' : 'wrong') : '', i === idx ? 'current' : ''].join(' '), 'aria-label': `Message ${i + 1}${a ? (a.correct ? ', correct' : ', incorrect') : ''}`, onclick: () => { idx = i; renderChallenge(); } }, i + 1);
    }));

    if (idx >= ITEMS.length) { area.replaceChildren(dots, summary()); return; }

    const c = ITEMS[idx];
    const a = answers[c.id];
    let verdict = a ? a.verdict : null;

    const msg = h('article', { class: 'msg' },
      h('div', { class: 'msg-head' },
        h('div', {}, h('span', { class: 'k' }, 'Type'), c.kind),
        h('div', {}, h('span', { class: 'k' }, 'From'), h('span', { class: 'mono' }, c.from)),
        h('div', {}, h('span', { class: 'k' }, 'Subject'), c.subject)),
      h('div', { class: 'msg-body' }, c.body));

    const vBtns = [['phish', 'Phishing'], ['legit', 'Legitimate']].map(([v, label]) =>
      h('button', { type: 'button', class: 'btn' + (verdict === v ? ' primary' : ''), 'aria-pressed': verdict === v, disabled: !!a, onclick: () => { verdict = v; vBtns.forEach(b => { const on = b.dataset.v === v; b.classList.toggle('primary', on); b.setAttribute('aria-pressed', on); }); submit.disabled = false; } }, label));
    vBtns.forEach((b, i) => { b.dataset.v = i ? 'legit' : 'phish'; });

    const flagInputs = [];
    const flagList = h('div', { class: 'flag-list' }, P.FLAG_CHOICES.map(fc => {
      const inp = h('input', { type: 'checkbox', value: fc.id, id: 'flag-' + fc.id, disabled: !!a, checked: a ? a.selected.includes(fc.id) : false });
      flagInputs.push(inp);
      let cls = '';
      if (a) cls = a.hit.includes(fc.id) ? 'hit' : a.wrong.includes(fc.id) ? 'wrong' : a.missed.includes(fc.id) ? 'miss' : '';
      return h('label', { for: 'flag-' + fc.id, class: cls }, inp, fc.label, a && a.missed.includes(fc.id) ? h('span', { class: 'hint' }, ' (missed)') : null);
    }));

    const submit = h('button', { type: 'button', class: 'btn primary', disabled: !verdict || !!a, onclick: () => {
      const selected = flagInputs.filter(i => i.checked).map(i => i.value);
      const correct = (verdict === 'phish') === c.phish;
      const rec = { id: c.id, verdict, correct, selected, hit: selected.filter(s => c.flags.includes(s)), missed: c.flags.filter(s => !selected.includes(s)), wrong: selected.filter(s => !c.flags.includes(s)), t: new Date().toISOString() };
      P.store.update(s => { s.challenge.answers[c.id] = rec; });
      renderChallenge();
    } }, 'Check answer');

    const side = h('div', { class: 'card' },
      h('h3', {}, `Message ${idx + 1} of ${ITEMS.length}`),
      h('div', { class: 'choice-row', role: 'group', 'aria-label': 'Your verdict' }, vBtns),
      h('div', { class: 'group-label' }, 'Red flags you spotted'),
      flagList);

    if (a) {
      side.append(h('div', { class: 'feedback ' + (a.correct ? 'right' : 'wrong') },
        h('b', {}, a.correct ? `Correct, this is ${c.phish ? 'phishing' : 'legitimate'}.` : `Not quite. This is ${c.phish ? 'phishing' : 'legitimate'}.`),
        h('p', {}, c.explain),
        c.flags.length ? h('p', { class: 'hint' }, `Red flags: ${a.hit.length} spotted, ${a.missed.length} missed, ${a.wrong.length} incorrect.`) : null),
        h('div', { class: 'row' },
          h('button', { type: 'button', class: 'btn primary', onclick: () => { idx = firstUnanswered(); if (idx === ITEMS.indexOf(c)) idx++; renderChallenge(); } }, firstUnanswered() >= ITEMS.length ? 'See my results' : 'Next message'),
          h('button', { type: 'button', class: 'btn ghost', onclick: () => { P.store.update(s => { delete s.challenge.answers[c.id]; }); renderChallenge(); } }, 'Try again')));
    } else {
      side.append(submit);
    }
    area.replaceChildren(dots, h('div', { class: 'challenge-grid' }, msg, side));
  }

  function summary() {
    const aw = P.awareness();
    const weak = Object.entries(aw.skillPct).filter(([, v]) => v !== null).sort((a, b) => a[1] - b[1]).slice(0, 3);
    return h('section', { class: 'card' },
      h('h3', {}, 'Your results'),
      h('div', { class: 'kpis' },
        kpi('Awareness score', aw.score ?? '—', P.grade(aw.score)),
        kpi('Correct verdicts', aw.accuracy == null ? '—' : Math.round(aw.accuracy * 100) + '%', `${aw.answered} answered`),
        kpi('Red-flag accuracy', aw.flagAcc == null ? '—' : Math.round(aw.flagAcc * 100) + '%', 'spotted vs missed/incorrect')),
      weak.length ? h('p', {}, 'Focus areas: ', weak.map(([k]) => P.SKILLS[k].name).join(', '), '. Your training plan has been ordered around these.') : null,
      h('div', { class: 'row' },
        h('button', { type: 'button', class: 'btn primary', onclick: () => P.showView('training') }, 'Open my training plan'),
        h('button', { type: 'button', class: 'btn ghost', onclick: () => { P.store.update(s => { s.challenge.answers = {}; }); idx = 0; renderChallenge(); } }, 'Restart challenge')));
  }

  function kpi(label, value, note) {
    return h('div', { class: 'kpi' }, h('span', { class: 'label' }, label), h('span', { class: 'value' }, String(value)), note ? h('span', { class: 'note' }, note) : null);
  }
  P.kpi = kpi;

  // ══════════ Training ══════════
  function plan() {
    const s = P.store.get();
    const aw = P.awareness();
    const recent = {};
    for (const hst of s.history.slice(-30)) for (const sk of hst.skills || []) recent[sk] = (recent[sk] || 0) + 1;
    const keys = Object.keys(P.SKILLS);
    const need = k => (aw.skillPct[k] ?? 0.6) - Math.min(0.3, (recent[k] || 0) * 0.05) + (s.training.done[k] ? 1 : 0);
    return { order: keys.sort((a, b) => need(a) - need(b)), aw, recent };
  }

  function renderTraining() {
    const s = P.store.get();
    const { order, aw, recent } = plan();
    $('training-progress').textContent = `${aw.done} / ${aw.total} complete · score ${aw.score ?? '—'}`;
    const focus = order.filter(k => !s.training.done[k]).slice(0, 3);
    const area = $('training-area');
    const intro = aw.answered ? null : h('p', { class: 'hint' }, 'Tip: take the Challenge first and this plan will be tailored to the areas you find hardest.');
    area.replaceChildren(...[intro, ...order.map(k => moduleEl(k, s, aw, recent, focus.includes(k)))].filter(Boolean));
  }

  function moduleEl(k, s, aw, recent, isFocus) {
    const m = P.TRAINING[k];
    const done = !!s.training.done[k];
    const pct = aw.skillPct[k];
    const why = [];
    if (pct !== null) why.push(`Challenge proficiency ${Math.round(pct * 100)}%`);
    if (recent[k]) why.push(`seen in ${recent[k]} message${recent[k] > 1 ? 's' : ''} you analysed`);
    const quizRes = s.training.quiz[k];
    const opts = m.quiz.options.map((o, i) => h('button', { type: 'button', class: quizRes !== undefined ? (i === m.quiz.answer ? 'right' : '') : '', onclick: e => answer(i, e.currentTarget) }, o));
    const result = h('p', { class: 'hint', role: 'status' }, quizRes !== undefined ? (quizRes ? 'You answered this correctly. ' : 'Reviewed. ') + m.quiz.why : '');
    function answer(i, btn) {
      const ok = i === m.quiz.answer;
      opts.forEach((b, j) => b.className = j === m.quiz.answer ? 'right' : '');
      if (!ok) btn.className = 'wrong';
      result.textContent = (ok ? 'Correct! ' : 'Not quite. ') + m.quiz.why;
      P.store.update(st => { if (st.training.quiz[k] === undefined) st.training.quiz[k] = ok; });
    }
    const det = h('details', { class: 'module', id: 'module-' + k },
      h('summary', {},
        h('span', { class: 'module-title' }, h('b', {}, P.SKILLS[k].name), h('small', {}, why.join(' · ') || 'Not assessed yet')),
        h('span', { class: 'status ' + (done ? 'done' : isFocus ? 'focus' : 'todo') }, done ? 'Complete' : isFocus ? 'Recommended' : 'To do')),
      h('div', { class: 'module-body' },
        h('p', {}, m.summary),
        h('div', { class: 'two-col' },
          h('div', {}, h('h4', {}, 'Tell-tale signs'), h('ul', {}, m.signs.map(x => h('li', {}, x)))),
          h('div', {}, h('h4', {}, 'What to do'), h('ul', {}, m.do.map(x => h('li', {}, x))))),
        h('div', { class: 'quiz' }, h('b', {}, 'Check yourself: ' + m.quiz.q), h('div', { class: 'opts' }, opts), result),
        h('div', { class: 'row' }, h('button', { type: 'button', class: 'btn ' + (done ? 'ghost' : 'primary'), onclick: () => { P.store.update(st => { st.training.done[k] = !done; }); renderTraining(); setTimeout(() => { const el = $('module-' + k); if (el) el.open = true; }, 0); } }, done ? 'Mark as not complete' : 'Mark lesson complete'))));
    return det;
  }

  document.addEventListener('pea:view', e => { if (e.detail === 'challenge') renderChallenge(); if (e.detail === 'training') renderTraining(); });
  document.addEventListener('pea:data', () => { if (!$('view-training').hidden) { /* keep open state: re-render only on explicit actions */ } });
  renderChallenge();
  renderTraining();
})();
